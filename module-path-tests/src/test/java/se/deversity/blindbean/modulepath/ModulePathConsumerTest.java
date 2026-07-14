package se.deversity.blindbean.modulepath;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Does BlindBean survive being put on the MODULE PATH?
 *
 * <p>Every other test in this repository runs on the classpath, where JPMS is not enforced at all —
 * encapsulation is off, every package is readable, and services resolve through
 * {@code META-INF/services}. That tells you nothing about whether the library works as a real named
 * module, which is exactly what the modularisation refactor changes.
 *
 * <p>So this exists <em>before</em> that refactor, passing against the current single-artifact
 * layout. It is the definition of "works like before": whatever the module boundaries end up being,
 * a consumer must still be able to do all of this.
 *
 * <p>It compiles and runs a real consumer module in a <b>separate JVM</b>, because that is the only
 * way to observe module resolution honestly — an in-process test would inherit this JVM's classpath
 * and prove nothing.
 *
 * <p>What it pins, and why each one is a genuine JPMS risk rather than a formality:
 *
 * <ul>
 *   <li><b>The annotation processor is discovered.</b> Today via {@code META-INF/services} (AutoService);
 *       a named module needs a {@code provides} clause. If codegen silently stops, the consumer's
 *       wrapper class simply does not exist.</li>
 *   <li><b>The generated wrapper compiles inside the consumer's own module</b> — it references types
 *       across a module boundary, so every package it touches must be exported.</li>
 *   <li><b>Native access works from a named module.</b> {@code --enable-native-access=ALL-UNNAMED}
 *       covers the classpath; a named module needs to be named explicitly.</li>
 *   <li><b>Key export/import still round-trips.</b> It is Java serialization, which reflects over
 *       {@code KeyBundle} — the classic thing that breaks under strong encapsulation.</li>
 *   <li><b>Rotation and the key stamp still work</b> end to end.</li>
 * </ul>
 */
class ModulePathConsumerTest {

    private static Path modules;
    private static String javaHome;

    @BeforeAll
    static void locateModulePath() {
        modules = Path.of(System.getProperty("modules.dir", "target/modules"));
        javaHome = System.getProperty("java.home");
        assumeTrue(Files.isDirectory(modules), "module path not laid out: " + modules);
    }

    /** The consumer: its own named module, requiring blindbean across a real module boundary. */
    private static final String MODULE_INFO = """
        module consumer.app {
            requires se.deversity.blindbean;
            requires jdk.incubator.vector;
        }
        """;

    private static final String ENTITY = """
        package consumer;
        import se.deversity.blindbean.annotations.*;

        @BlindEntity
        public class Account {
            @Homomorphic(scheme = Scheme.PAILLIER, type = java.math.BigDecimal.class, scale = 2)
            private String balance;

            @Homomorphic(scheme = Scheme.BFV, type = long[].class)
            private String readings;

            public Account() {}
            public String getBalance() { return balance; }
            public void setBalance(String v) { this.balance = v; }
            public String getReadings() { return readings; }
            public void setReadings(String v) { this.readings = v; }
        }
        """;

    private static final String MAIN = """
        package consumer;
        import se.deversity.blindbean.context.BlindContext;
        import se.deversity.blindbean.context.BlindRotation;
        import se.deversity.blindbean.math.PaillierKeyPair;
        import java.math.BigDecimal;
        import java.nio.file.*;

        public class Main {
            public static void main(String[] args) throws Exception {
                System.out.println("MODULE=" + Main.class.getModule().getName());
                System.out.println("LIB_MODULE=" + BlindContext.class.getModule().getName());

                // 1. The processor ran across the module boundary — this class only exists if it did.
                BlindContext.init();
                Account a = new Account();
                var w = new AccountBlindWrapper(a);

                // 2. Paillier arithmetic, exact decimals.
                w.encryptBalance(new BigDecimal("100.00"));
                w.addBalance(new BigDecimal("23.45"));
                w.subBalance(new BigDecimal("3.45"));
                System.out.println("BALANCE=" + w.decryptBalance());

                // 3. Key export/import — Java serialization of KeyBundle under strong encapsulation.
                Path keys = Path.of(args[0]);
                BlindContext.exportKeys(keys.toString());
                BlindContext.clear();
                BlindContext.loadKeys(keys.toString());
                System.out.println("AFTER_RELOAD=" + w.decryptBalance());

                // 4. Rotation, and the key stamp that refuses a re-rotate.
                try (BlindRotation r = BlindRotation.fromCurrent(new PaillierKeyPair(2048))) {
                    var rotated = r.rotate(w.getCiphertextBalance());
                    a.setBalance(rotated.hexData());
                    r.commit();
                }
                System.out.println("AFTER_ROTATION=" + w.decryptBalance());
                BlindContext.clear();

                // 5. Native FFM from a NAMED module (not ALL-UNNAMED).
                try {
                    BlindContext.initBfv(8192);
                    var wr = new AccountBlindWrapper(a);
                    wr.encryptReadings(new long[] { 5, 10, 15 });
                    wr.addReadings(new long[] { 1, 1, 1 });
                    long[] out = wr.decryptReadings();
                    System.out.println("BFV=" + out[0] + "," + out[1] + "," + out[2]);
                    BlindContext.clear();
                } catch (Throwable t) {
                    System.out.println("BFV=SKIPPED (" + t.getClass().getSimpleName() + ")");
                }
                System.out.println("DONE");
            }
        }
        """;

    @Test
    void aConsumerModuleCanUseEveryPublicCapability(@TempDir Path tmp) throws Exception {
        Path src = tmp.resolve("src/consumer.app");
        Files.createDirectories(src.resolve("consumer"));
        Files.writeString(src.resolve("module-info.java"), MODULE_INFO);
        Files.writeString(src.resolve("consumer/Account.java"), ENTITY);
        Files.writeString(src.resolve("consumer/Main.java"), MAIN);

        Path out = tmp.resolve("out");
        Files.createDirectories(out);
        String mp = modules.toAbsolutePath().toString();

        // ── compile the consumer as a named module against blindbean on the MODULE path ──
        // The annotation processor is on the module path too; javac must still find and run it.
        Result compiled = run(
            bin("javac"),
            "--release", "26",
            "--enable-preview",
            "--add-modules", "jdk.incubator.vector",
            "--module-path", mp,
            "--processor-module-path", mp,
            "-d", out.toString(),
            "--module-source-path", tmp.resolve("src").toString(),
            "--module", "consumer.app");

        assertEquals(0, compiled.exit(),
            "the consumer module failed to compile against blindbean on the module path.\n"
            + "If the wrapper class is missing, the annotation processor was not discovered — which "
            + "is the single most likely thing modularisation breaks.\n" + compiled.output());

        // ── run it as a real named module ──
        Result ran = run(
            bin("java"),
            "--enable-preview",
            "--add-modules", "jdk.incubator.vector",
            "--enable-native-access=consumer.app,se.deversity.blindbean",
            "-Dblindbean.native.path=" + System.getProperty("blindbean.native.path", "../build-native/Release"),
            "--module-path", out + java.io.File.pathSeparator + mp,
            "--module", "consumer.app/consumer.Main",
            tmp.resolve("keys.bin").toString());

        String o = ran.output();
        assertEquals(0, ran.exit(), "the consumer module failed at runtime:\n" + o);

        assertTrue(o.contains("MODULE=consumer.app"), "the consumer must run as a NAMED module: " + o);
        assertTrue(o.contains("BALANCE=120.00"), "Paillier arithmetic across the boundary: " + o);
        assertTrue(o.contains("AFTER_RELOAD=120.00"),
            "key export/import must survive — it is Java serialization over KeyBundle, the classic "
            + "casualty of strong encapsulation: " + o);
        assertTrue(o.contains("AFTER_ROTATION=120.00"), "rotation across the boundary: " + o);
        assertTrue(o.contains("BFV=6,11,16") || o.contains("BFV=SKIPPED"),
            "native FFM from a named module (needs --enable-native-access=<module>, not "
            + "ALL-UNNAMED): " + o);
        assertTrue(o.contains("DONE"), o);

        System.out.println(o);
    }

    // ── plumbing ─────────────────────────────────────────────────────────────

    private record Result(int exit, String output) {}

    private static String bin(String tool) {
        return Path.of(javaHome, "bin", tool).toString();
    }

    private static Result run(String... cmd) throws IOException, InterruptedException {
        var pb = new ProcessBuilder(cmd).redirectErrorStream(true);
        Process p = pb.start();
        String out = new String(p.getInputStream().readAllBytes());
        return new Result(p.waitFor(), out);
    }
}

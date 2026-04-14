package com.blindbean.processor;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.tools.*;
import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Compile-time APT test for HomomorphicProcessor.
 *
 * Uses javax.tools.JavaCompiler to compile synthetic @BlindEntity sources in a
 * temp directory, runs the processor, then loads the generated class and
 * asserts method presence / compilation errors.
 */
public class HomomorphicProcessorTest {

    // ── helpers ──────────────────────────────────────────────────────────────

    /**
     * Compiles the given source text under the given class name and returns
     * the list of diagnostics.  Generated sources land in {@code genDir},
     * compiled classes in {@code classesDir}.
     */
    private List<Diagnostic<? extends JavaFileObject>> compile(
            String className, String source, Path genDir, Path classesDir) throws IOException {

        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        assertNotNull(compiler, "System Java compiler not available");

        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();

        // Write the source file
        Path srcFile = classesDir.getParent().resolve(className + ".java");
        Files.writeString(srcFile, source);

        // Build the classpath from the current test classpath so the processor
        // and blindbean classes are visible to the in-process compiler.
        String cp = System.getProperty("java.class.path");

        StandardJavaFileManager fm = compiler.getStandardFileManager(diagnostics, Locale.ROOT, null);

        List<String> options = Arrays.asList(
            "-classpath", cp,
            "-processorpath", cp,
            "-processor", "com.blindbean.processor.HomomorphicProcessor",
            "-s", genDir.toAbsolutePath().toString(),
            "-d", classesDir.toAbsolutePath().toString(),
            "--enable-preview",
            "--release", "26",
            "--add-modules", "jdk.incubator.vector"
        );

        Iterable<? extends JavaFileObject> units =
            fm.getJavaFileObjects(srcFile.toFile());

        JavaCompiler.CompilationTask task =
            compiler.getTask(new StringWriter(), fm, diagnostics, options, null, units);

        task.call();

        fm.close();
        return diagnostics.getDiagnostics();
    }

    /** Returns a URLClassLoader that can load from classesDir (and the normal test CP). */
    private URLClassLoader loaderFor(Path classesDir) throws Exception {
        return new URLClassLoader(
            new java.net.URL[]{ classesDir.toUri().toURL() },
            Thread.currentThread().getContextClassLoader());
    }

    // ── Positive tests ────────────────────────────────────────────────────

    @Test
    public void paillierFieldGeneratesCorrectMethods(@TempDir Path tmpDir) throws Exception {
        Path genDir     = tmpDir.resolve("gen");
        Path classesDir = tmpDir.resolve("classes");
        Files.createDirectories(genDir);
        Files.createDirectories(classesDir);

        String source = """
            package com.example.apt;

            import com.blindbean.annotations.BlindEntity;
            import com.blindbean.annotations.Homomorphic;
            import com.blindbean.annotations.Scheme;

            @BlindEntity
            public class PaillierEntity {
                @Homomorphic(scheme = Scheme.PAILLIER)
                private String balance;

                public PaillierEntity(String b) { this.balance = b; }

                public String getBalance() { return balance; }
                public void setBalance(String b) { this.balance = b; }
            }
            """;

        List<Diagnostic<? extends JavaFileObject>> diags =
            compile("PaillierEntity", source, genDir, classesDir);

        // Should have no errors
        long errors = diags.stream()
            .filter(d -> d.getKind() == Diagnostic.Kind.ERROR)
            .count();
        assertEquals(0, errors, "Expected no compilation errors; got: " + diags);

        // Wrapper source must exist
        Path wrapper = genDir.resolve("com/example/apt/PaillierEntityBlindWrapper.java");
        assertTrue(Files.exists(wrapper), "Wrapper source not generated: " + wrapper);

        String wrapperSrc = Files.readString(wrapper);
        assertTrue(wrapperSrc.contains("getCiphertextBalance"), "Missing getCiphertextBalance");
        assertTrue(wrapperSrc.contains("encryptBalance"),       "Missing encryptBalance");
        assertTrue(wrapperSrc.contains("decryptBalance"),       "Missing decryptBalance");
        assertTrue(wrapperSrc.contains("addBalance"),           "Missing addBalance");
        assertFalse(wrapperSrc.contains("mulBalance"),          "PAILLIER must NOT have mulBalance");
    }

    @Test
    public void bfvFieldGeneratesAddAndMul(@TempDir Path tmpDir) throws Exception {
        Path genDir     = tmpDir.resolve("gen");
        Path classesDir = tmpDir.resolve("classes");
        Files.createDirectories(genDir);
        Files.createDirectories(classesDir);

        String source = """
            package com.example.apt;

            import com.blindbean.annotations.BlindEntity;
            import com.blindbean.annotations.Homomorphic;
            import com.blindbean.annotations.Scheme;

            @BlindEntity
            public class BfvEntity {
                @Homomorphic(scheme = Scheme.BFV)
                private String counter;

                public BfvEntity(String c) { this.counter = c; }

                public String getCounter() { return counter; }
                public void setCounter(String c) { this.counter = c; }
            }
            """;

        List<Diagnostic<? extends JavaFileObject>> diags =
            compile("BfvEntity", source, genDir, classesDir);

        long errors = diags.stream()
            .filter(d -> d.getKind() == Diagnostic.Kind.ERROR)
            .count();
        assertEquals(0, errors, "Expected no compilation errors; got: " + diags);

        Path wrapper = genDir.resolve("com/example/apt/BfvEntityBlindWrapper.java");
        assertTrue(Files.exists(wrapper), "Wrapper source not generated");

        String wrapperSrc = Files.readString(wrapper);
        assertTrue(wrapperSrc.contains("getCiphertextCounter"), "Missing getCiphertextCounter");
        assertTrue(wrapperSrc.contains("encryptCounter"),       "Missing encryptCounter");
        assertTrue(wrapperSrc.contains("decryptCounter"),       "Missing decryptCounter");
        assertTrue(wrapperSrc.contains("addCounter"),           "Missing addCounter");
        assertTrue(wrapperSrc.contains("mulCounter"),           "BFV must have mulCounter");
    }

    // ── Negative tests ────────────────────────────────────────────────────

    @Test
    public void nonStringFieldCausesAptError(@TempDir Path tmpDir) throws Exception {
        Path genDir     = tmpDir.resolve("gen");
        Path classesDir = tmpDir.resolve("classes");
        Files.createDirectories(genDir);
        Files.createDirectories(classesDir);

        String source = """
            package com.example.apt;

            import com.blindbean.annotations.BlindEntity;
            import com.blindbean.annotations.Homomorphic;
            import com.blindbean.annotations.Scheme;

            @BlindEntity
            public class BadFieldEntity {
                @Homomorphic(scheme = Scheme.PAILLIER)
                private int amount;   // must be String

                public BadFieldEntity(int a) { this.amount = a; }

                public int getAmount() { return amount; }
                public void setAmount(int a) { this.amount = a; }
            }
            """;

        List<Diagnostic<? extends JavaFileObject>> diags =
            compile("BadFieldEntity", source, genDir, classesDir);

        boolean hasAptError = diags.stream()
            .filter(d -> d.getKind() == Diagnostic.Kind.ERROR)
            .anyMatch(d -> {
                String msg = d.getMessage(Locale.ROOT);
                return msg.contains("must be of type String") || msg.contains("String");
            });

        assertTrue(hasAptError,
            "Expected APT error for non-String field; diagnostics: " + diags);
    }

    @Test
    public void missingGetterCausesAptError(@TempDir Path tmpDir) throws Exception {
        Path genDir     = tmpDir.resolve("gen");
        Path classesDir = tmpDir.resolve("classes");
        Files.createDirectories(genDir);
        Files.createDirectories(classesDir);

        String source = """
            package com.example.apt;

            import com.blindbean.annotations.BlindEntity;
            import com.blindbean.annotations.Homomorphic;
            import com.blindbean.annotations.Scheme;

            @BlindEntity
            public class NoGetterEntity {
                @Homomorphic(scheme = Scheme.PAILLIER)
                private String secret;

                public NoGetterEntity(String s) { this.secret = s; }
                // Deliberately missing getSecret()
                public void setSecret(String s) { this.secret = s; }
            }
            """;

        List<Diagnostic<? extends JavaFileObject>> diags =
            compile("NoGetterEntity", source, genDir, classesDir);

        boolean hasAptError = diags.stream()
            .filter(d -> d.getKind() == Diagnostic.Kind.ERROR)
            .anyMatch(d -> {
                String msg = d.getMessage(Locale.ROOT);
                return msg.contains("getter") || msg.contains("getSecret");
            });

        assertTrue(hasAptError,
            "Expected APT error for missing getter; diagnostics: " + diags);
    }

    @Test
    public void elgamalSchemeCausesAptError(@TempDir Path tmpDir) throws Exception {
        Path genDir     = tmpDir.resolve("gen");
        Path classesDir = tmpDir.resolve("classes");
        Files.createDirectories(genDir);
        Files.createDirectories(classesDir);

        String source = """
            package com.example.apt;

            import com.blindbean.annotations.BlindEntity;
            import com.blindbean.annotations.Homomorphic;
            import com.blindbean.annotations.Scheme;

            @BlindEntity
            public class ElgamalEntity {
                @Homomorphic(scheme = Scheme.ELGAMAL)
                private String cipher;

                public ElgamalEntity(String c) { this.cipher = c; }

                public String getCipher() { return cipher; }
                public void setCipher(String c) { this.cipher = c; }
            }
            """;

        List<Diagnostic<? extends JavaFileObject>> diags =
            compile("ElgamalEntity", source, genDir, classesDir);

        boolean hasAptError = diags.stream()
            .filter(d -> d.getKind() == Diagnostic.Kind.ERROR)
            .anyMatch(d -> {
                String msg = d.getMessage(Locale.ROOT);
                return msg.contains("ELGAMAL") || msg.contains("not supported");
            });

        assertTrue(hasAptError,
            "Expected APT error for ELGAMAL scheme; diagnostics: " + diags);
    }
}

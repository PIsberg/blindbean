package se.deversity.blindbean.processor;

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
            "-processor", "se.deversity.blindbean.processor.HomomorphicProcessor",
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

            import se.deversity.blindbean.annotations.BlindEntity;
            import se.deversity.blindbean.annotations.Homomorphic;
            import se.deversity.blindbean.annotations.Scheme;

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
        assertTrue(wrapperSrc.contains("addBalance(Ciphertext other)"), "Missing addBalance");
        assertTrue(wrapperSrc.contains("subBalance(Ciphertext other)"), "Missing subBalance");
        assertTrue(wrapperSrc.contains("addBalance(BigInteger plain)"), "Missing addBalance plain");
        assertTrue(wrapperSrc.contains("subBalance(BigInteger plain)"), "Missing subBalance plain");
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

            import se.deversity.blindbean.annotations.BlindEntity;
            import se.deversity.blindbean.annotations.Homomorphic;
            import se.deversity.blindbean.annotations.Scheme;

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
        assertTrue(wrapperSrc.contains("addCounter(Ciphertext other)"), "Missing addCounter");
        assertTrue(wrapperSrc.contains("subCounter(Ciphertext other)"), "Missing subCounter");
        assertTrue(wrapperSrc.contains("mulCounter(Ciphertext other)"), "Missing mulCounter");
        assertTrue(wrapperSrc.contains("addCounter(long plain)"), "Missing addCounter plain");
        assertTrue(wrapperSrc.contains("subCounter(long plain)"), "Missing subCounter plain");
        assertTrue(wrapperSrc.contains("mulCounter(long plain)"), "Missing mulCounter plain");
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

            import se.deversity.blindbean.annotations.BlindEntity;
            import se.deversity.blindbean.annotations.Homomorphic;
            import se.deversity.blindbean.annotations.Scheme;

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
    public void typedFieldsGenerateCorrectSignatures(@TempDir Path tmpDir) throws Exception {
        Path genDir     = tmpDir.resolve("gen");
        Path classesDir = tmpDir.resolve("classes");
        Files.createDirectories(genDir);
        Files.createDirectories(classesDir);

        String source = """
            package com.example.apt;

            import se.deversity.blindbean.annotations.BlindEntity;
            import se.deversity.blindbean.annotations.Homomorphic;
            import se.deversity.blindbean.annotations.Scheme;

            @BlindEntity
            public class TypedEntity {
                @Homomorphic(scheme = Scheme.PAILLIER, type = String.class)
                private String username;

                @Homomorphic(scheme = Scheme.PAILLIER, type = boolean.class)
                private String flag;

                public TypedEntity(String u, String f) { this.username = u; this.flag = f; }

                public String getUsername() { return username; }
                public void setUsername(String u) { this.username = u; }

                public String getFlag() { return flag; }
                public void setFlag(String f) { this.flag = f; }
            }
            """;

        List<Diagnostic<? extends JavaFileObject>> diags =
            compile("TypedEntity", source, genDir, classesDir);

        long errors = diags.stream()
            .filter(d -> d.getKind() == Diagnostic.Kind.ERROR)
            .count();
        assertEquals(0, errors, "Expected no compilation errors; got: " + diags);

        Path wrapper = genDir.resolve("com/example/apt/TypedEntityBlindWrapper.java");
        assertTrue(Files.exists(wrapper), "Wrapper source not generated");

        String wrapperSrc = Files.readString(wrapper);
        assertTrue(wrapperSrc.contains("encryptUsername(String plain)"), "Missing encryptUsername(String)");
        assertTrue(wrapperSrc.contains("String decryptUsername()"), "Missing String decryptUsername()");
        assertFalse(wrapperSrc.contains("addUsername"), "String should not support add");

        assertTrue(wrapperSrc.contains("encryptFlag(boolean plain)"), "Missing encryptFlag(boolean)");
        assertTrue(wrapperSrc.contains("boolean decryptFlag()"), "Missing boolean decryptFlag()");
        assertFalse(wrapperSrc.contains("addFlag"), "Boolean should not support add");
    }

    @Test
    public void missingGetterCausesAptError(@TempDir Path tmpDir) throws Exception {
        Path genDir     = tmpDir.resolve("gen");
        Path classesDir = tmpDir.resolve("classes");
        Files.createDirectories(genDir);
        Files.createDirectories(classesDir);

        String source = """
            package com.example.apt;

            import se.deversity.blindbean.annotations.BlindEntity;
            import se.deversity.blindbean.annotations.Homomorphic;
            import se.deversity.blindbean.annotations.Scheme;

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

            import se.deversity.blindbean.annotations.BlindEntity;
            import se.deversity.blindbean.annotations.Homomorphic;
            import se.deversity.blindbean.annotations.Scheme;

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

        // ELGAMAL was removed from Scheme; the Java compiler now rejects
        // "Scheme.ELGAMAL" as a non-existent enum constant before the APT even runs.
        // Accept any error diagnostic — APT message ("ELGAMAL"/"not supported") OR
        // a javac enum-constant error ("enum constant" / "cannot find symbol").
        boolean hasAptError = diags.stream()
            .filter(d -> d.getKind() == Diagnostic.Kind.ERROR)
            .anyMatch(d -> {
                String msg = d.getMessage(Locale.ROOT);
                return msg.contains("ELGAMAL") || msg.contains("not supported")
                    || msg.contains("enum constant") || msg.contains("cannot find symbol");
            });

        assertTrue(hasAptError,
            "Expected compile error for removed Scheme.ELGAMAL; diagnostics: " + diags);
    }

    /**
     * The generated Paillier String round-trip must be byte-exact. encrypt() encodes the UTF-8
     * bytes as an unsigned magnitude (new BigInteger(1, bytes)), so decrypt() must strip the sign
     * byte that toByteArray() prepends whenever the leading byte is >= 0x80 — otherwise every
     * string starting with a non-ASCII character comes back with a leading NUL.
     */
    @Test
    public void paillierStringRoundTripsNonAsciiExactly(@TempDir Path tmpDir) throws Exception {
        Path genDir     = tmpDir.resolve("gen");
        Path classesDir = tmpDir.resolve("classes");
        Files.createDirectories(genDir);
        Files.createDirectories(classesDir);

        String source = """
            package com.example.apt;

            import se.deversity.blindbean.annotations.BlindEntity;
            import se.deversity.blindbean.annotations.Homomorphic;
            import se.deversity.blindbean.annotations.Scheme;

            @BlindEntity
            public class SecretNote {
                @Homomorphic(scheme = Scheme.PAILLIER, type = String.class)
                private String note;

                public String getNote() { return note; }
                public void setNote(String n) { this.note = n; }
            }
            """;

        List<Diagnostic<? extends JavaFileObject>> diags =
            compile("SecretNote", source, genDir, classesDir);
        assertEquals(0, diags.stream().filter(d -> d.getKind() == Diagnostic.Kind.ERROR).count(),
            "Expected no compilation errors; got: " + diags);

        se.deversity.blindbean.context.BlindContext.init();
        try (URLClassLoader loader = loaderFor(classesDir)) {
            Class<?> entityClass  = loader.loadClass("com.example.apt.SecretNote");
            Class<?> wrapperClass = loader.loadClass("com.example.apt.SecretNoteBlindWrapper");

            Object entity  = entityClass.getConstructor().newInstance();
            Object wrapper = wrapperClass.getConstructor(entityClass).newInstance(entity);

            var encrypt = wrapperClass.getMethod("encryptNote", String.class);
            var decrypt = wrapperClass.getMethod("decryptNote");

            // "é" is 0xC3 0xA9 — a leading byte >= 0x80, which is what triggers the sign byte.
            for (String plain : List.of("élan vital", "hello", "ünïcødé ✓", "")) {
                encrypt.invoke(wrapper, plain);
                assertEquals(plain, decrypt.invoke(wrapper),
                    "Paillier String round-trip must be exact for: " + plain);
            }
        } finally {
            se.deversity.blindbean.context.BlindContext.clear();
        }
    }

    /**
     * The generated rotate<Field>(BlindRotation) hook must re-encrypt the stored ciphertext in
     * place, so a consumer rotating keys never handles plaintext and never hand-rolls a
     * decrypt/encrypt loop.
     */
    @Test
    public void generatedWrapperRotatesAPaillierFieldInPlace(@TempDir Path tmpDir) throws Exception {
        Path genDir     = tmpDir.resolve("gen");
        Path classesDir = tmpDir.resolve("classes");
        Files.createDirectories(genDir);
        Files.createDirectories(classesDir);

        String source = """
            package com.example.apt;

            import se.deversity.blindbean.annotations.BlindEntity;
            import se.deversity.blindbean.annotations.Homomorphic;
            import se.deversity.blindbean.annotations.Scheme;

            @BlindEntity
            public class Account {
                @Homomorphic(scheme = Scheme.PAILLIER, type = long.class)
                private String balance;

                public String getBalance() { return balance; }
                public void setBalance(String b) { this.balance = b; }
            }
            """;

        List<Diagnostic<? extends JavaFileObject>> diags =
            compile("Account", source, genDir, classesDir);
        assertEquals(0, diags.stream().filter(d -> d.getKind() == Diagnostic.Kind.ERROR).count(),
            "Expected no compilation errors; got: " + diags);

        assertTrue(Files.readString(genDir.resolve("com/example/apt/AccountBlindWrapper.java"))
                .contains("rotateBalance(BlindRotation rotation)"),
            "Paillier fields must get a rotation hook");

        se.deversity.blindbean.context.BlindContext.init();
        try (URLClassLoader loader = loaderFor(classesDir)) {
            Class<?> entityClass  = loader.loadClass("com.example.apt.Account");
            Class<?> wrapperClass = loader.loadClass("com.example.apt.AccountBlindWrapper");

            Object entity  = entityClass.getConstructor().newInstance();
            Object wrapper = wrapperClass.getConstructor(entityClass).newInstance(entity);

            wrapperClass.getMethod("encryptBalance", long.class).invoke(wrapper, 5000L);
            String beforeRotation = (String) entityClass.getMethod("getBalance").invoke(entity);

            var newKeys = new se.deversity.blindbean.math.PaillierKeyPair(512);
            try (var rotation = se.deversity.blindbean.context.BlindRotation.fromCurrent(newKeys)) {
                wrapperClass.getMethod("rotateBalance", se.deversity.blindbean.context.BlindRotation.class)
                    .invoke(wrapper, rotation);
                rotation.commit();
            }

            String afterRotation = (String) entityClass.getMethod("getBalance").invoke(entity);
            assertNotEquals(beforeRotation, afterRotation,
                "the stored ciphertext must have been re-encrypted under the new keys");
            assertEquals(5000L, wrapperClass.getMethod("decryptBalance").invoke(wrapper),
                "the rotated field must still decrypt to the original value, now under the new keys");
        } finally {
            se.deversity.blindbean.context.BlindContext.clear();
        }
    }

    @Test
    public void everySchemeGetsARotationHook(@TempDir Path tmpDir) throws Exception {
        Path genDir     = tmpDir.resolve("gen");
        Path classesDir = tmpDir.resolve("classes");
        Files.createDirectories(genDir);
        Files.createDirectories(classesDir);

        String source = """
            package com.example.apt;

            import se.deversity.blindbean.annotations.BlindEntity;
            import se.deversity.blindbean.annotations.Homomorphic;
            import se.deversity.blindbean.annotations.Scheme;

            @BlindEntity
            public class Reading {
                @Homomorphic(scheme = Scheme.BFV, type = long.class)
                private String value;

                public String getValue() { return value; }
                public void setValue(String v) { this.value = v; }
            }
            """;

        List<Diagnostic<? extends JavaFileObject>> diags =
            compile("Reading", source, genDir, classesDir);
        assertEquals(0, diags.stream().filter(d -> d.getKind() == Diagnostic.Kind.ERROR).count(),
            "Expected no compilation errors; got: " + diags);

        // Rotation is ciphertext-level, so BFV/CKKS fields get the hook too.
        assertTrue(Files.readString(genDir.resolve("com/example/apt/ReadingBlindWrapper.java"))
                .contains("rotateValue(BlindRotation rotation)"),
            "BFV fields must get a rotation hook now that native rotation is implemented");
    }

    @Test
    public void allNumericPrimitivesGenerateCorrectSignatures(@TempDir Path tmpDir) throws Exception {
        Path genDir     = tmpDir.resolve("gen");
        Path classesDir = tmpDir.resolve("classes");
        Files.createDirectories(genDir);
        Files.createDirectories(classesDir);

        String source = """
            package com.example.apt;

            import se.deversity.blindbean.annotations.BlindEntity;
            import se.deversity.blindbean.annotations.Homomorphic;
            import se.deversity.blindbean.annotations.Scheme;

            @BlindEntity
            public class NumericPrimitivesEntity {
                @Homomorphic(scheme = Scheme.PAILLIER, type = byte.class)
                private String b;
                @Homomorphic(scheme = Scheme.PAILLIER, type = short.class)
                private String s;
                @Homomorphic(scheme = Scheme.PAILLIER, type = int.class)
                private String i;
                @Homomorphic(scheme = Scheme.BFV, type = long.class)
                private String l;
                @Homomorphic(scheme = Scheme.CKKS, type = float.class)
                private String f;
                @Homomorphic(scheme = Scheme.CKKS, type = double.class)
                private String d;

                public NumericPrimitivesEntity() {}

                public String getB() { return b; }
                public void setB(String b) { this.b = b; }
                public String getS() { return s; }
                public void setS(String s) { this.s = s; }
                public String getI() { return i; }
                public void setI(String i) { this.i = i; }
                public String getL() { return l; }
                public void setL(String l) { this.l = l; }
                public String getF() { return f; }
                public void setF(String f) { this.f = f; }
                public String getD() { return d; }
                public void setD(String d) { this.d = d; }
            }
            """;

        List<Diagnostic<? extends JavaFileObject>> diags =
            compile("NumericPrimitivesEntity", source, genDir, classesDir);

        long errors = diags.stream()
            .filter(d -> d.getKind() == Diagnostic.Kind.ERROR)
            .count();
        assertEquals(0, errors, "Expected no compilation errors; got: " + diags);

        Path wrapper = genDir.resolve("com/example/apt/NumericPrimitivesEntityBlindWrapper.java");
        assertTrue(Files.exists(wrapper), "Wrapper source not generated");

        String wrapperSrc = Files.readString(wrapper);
        
        // Assertions for byte (Paillier)
        assertTrue(wrapperSrc.contains("encryptB(byte plain)"), "Missing byte encryption");
        assertTrue(wrapperSrc.contains("byte decryptB()"), "Missing byte decryption");
        assertTrue(wrapperSrc.contains("java.math.BigInteger.valueOf(plain)"), "Missing byte-to-BigInteger conversion");

        // Assertions for short (Paillier)
        assertTrue(wrapperSrc.contains("encryptS(short plain)"), "Missing short encryption");
        assertTrue(wrapperSrc.contains("short decryptS()"), "Missing short decryption");

        // Assertions for int (Paillier)
        assertTrue(wrapperSrc.contains("encryptI(int plain)"), "Missing int encryption");
        assertTrue(wrapperSrc.contains("int decryptI()"), "Missing int decryption");
        assertTrue(wrapperSrc.contains("addI(BigInteger plain)"), "Missing int math");

        // Assertions for long (BFV)
        assertTrue(wrapperSrc.contains("encryptL(long plain)"), "Missing long encryption");
        assertTrue(wrapperSrc.contains("long decryptL()"), "Missing long decryption");
        assertTrue(wrapperSrc.contains("addL(long plain)"), "Missing long math");

        // Assertions for float (CKKS)
        assertTrue(wrapperSrc.contains("encryptF(float plain)"), "Missing float encryption");
        assertTrue(wrapperSrc.contains("float decryptF()"), "Missing float decryption");
        assertTrue(wrapperSrc.contains("ctx.encryptDouble((double)plain)"), "Missing float-to-double widening");

        // Assertions for double (CKKS)
        assertTrue(wrapperSrc.contains("encryptD(double plain)"), "Missing double encryption");
        assertTrue(wrapperSrc.contains("double decryptD()"), "Missing double decryption");
    }

    @Test
    public void boxedNumericTypesGenerateCorrectSignatures(@TempDir Path tmpDir) throws Exception {
        Path genDir     = tmpDir.resolve("gen");
        Path classesDir = tmpDir.resolve("classes");
        Files.createDirectories(genDir);
        Files.createDirectories(classesDir);

        String source = """
            package com.example.apt;

            import se.deversity.blindbean.annotations.BlindEntity;
            import se.deversity.blindbean.annotations.Homomorphic;
            import se.deversity.blindbean.annotations.Scheme;

            @BlindEntity
            public class BoxedNumericEntity {
                @Homomorphic(scheme = Scheme.PAILLIER, type = Integer.class)
                private String i;
                @Homomorphic(scheme = Scheme.BFV, type = Long.class)
                private String l;
                @Homomorphic(scheme = Scheme.CKKS, type = Double.class)
                private String d;

                public BoxedNumericEntity() {}
                public String getI() { return i; }
                public void setI(String i) { this.i = i; }
                public String getL() { return l; }
                public void setL(String l) { this.l = l; }
                public String getD() { return d; }
                public void setD(String d) { this.d = d; }
            }
            """;

        List<Diagnostic<? extends JavaFileObject>> diags =
            compile("BoxedNumericEntity", source, genDir, classesDir);

        assertEquals(0, diags.stream().filter(d -> d.getKind() == Diagnostic.Kind.ERROR).count());

        Path wrapper = genDir.resolve("com/example/apt/BoxedNumericEntityBlindWrapper.java");
        String wrapperSrc = Files.readString(wrapper);
        
        assertTrue(wrapperSrc.contains("encryptI(int plain)"), "Boxed Integer should use int primitive parameter");
        assertTrue(wrapperSrc.contains("Integer decryptI()"), "Boxed Integer should return Integer wrapper");
        assertTrue(wrapperSrc.contains("encryptL(long plain)"), "Boxed Long should use long primitive parameter");
        assertTrue(wrapperSrc.contains("Long decryptL()"), "Boxed Long should return Long wrapper");
        assertTrue(wrapperSrc.contains("encryptD(double plain)"), "Boxed Double should use double primitive parameter");
        assertTrue(wrapperSrc.contains("Double decryptD()"), "Boxed Double should return Double wrapper");
    }

    @Test
    public void mathOperationsAcrossAllSchemes(@TempDir Path tmpDir) throws Exception {
        Path genDir     = tmpDir.resolve("gen");
        Path classesDir = tmpDir.resolve("classes");
        Files.createDirectories(genDir);
        Files.createDirectories(classesDir);

        String source = """
            package com.example.apt;

            import se.deversity.blindbean.annotations.BlindEntity;
            import se.deversity.blindbean.annotations.Homomorphic;
            import se.deversity.blindbean.annotations.Scheme;

            @BlindEntity
            public class MathEntity {
                @Homomorphic(scheme = Scheme.PAILLIER, type = int.class)
                private String i;
                @Homomorphic(scheme = Scheme.BFV, type = long.class)
                private String l;
                @Homomorphic(scheme = Scheme.CKKS, type = double.class)
                private String d;

                public MathEntity() {}
                public String getI() { return i; }
                public void setI(String i) { this.i = i; }
                public String getL() { return l; }
                public void setL(String l) { this.l = l; }
                public String getD() { return d; }
                public void setD(String d) { this.d = d; }
            }
            """;

        compile("MathEntity", source, genDir, classesDir);
        Path wrapper = genDir.resolve("com/example/apt/MathEntityBlindWrapper.java");
        String wrapperSrc = Files.readString(wrapper);
        
        // Paillier Math
        assertTrue(wrapperSrc.contains("addI(BigInteger plain)"), "Missing Paillier Add Plain");
        assertTrue(wrapperSrc.contains("subI(BigInteger plain)"), "Missing Paillier Sub Plain");

        // BFV Math
        assertTrue(wrapperSrc.contains("addL(long plain)"), "Missing BFV Add Plain");
        assertTrue(wrapperSrc.contains("subL(long plain)"), "Missing BFV Sub Plain");
        assertTrue(wrapperSrc.contains("mulL(long plain)"), "Missing BFV Mul Plain");

        // CKKS Math
        assertTrue(wrapperSrc.contains("addD(double plain)"), "Missing CKKS Add Plain");
        assertTrue(wrapperSrc.contains("subD(double plain)"), "Missing CKKS Sub Plain");
        assertTrue(wrapperSrc.contains("mulD(double plain)"), "Missing CKKS Mul Plain");
    }

    @Test
    public void asyncMethodsAreGenerated(@TempDir Path tmpDir) throws Exception {
        Path genDir     = tmpDir.resolve("gen");
        Path classesDir = tmpDir.resolve("classes");
        Files.createDirectories(genDir);
        Files.createDirectories(classesDir);

        String source = """
            package com.example.apt;

            import se.deversity.blindbean.annotations.BlindEntity;
            import se.deversity.blindbean.annotations.Homomorphic;
            import se.deversity.blindbean.annotations.Scheme;

            @BlindEntity(async = true)
            public class AsyncEntity {
                @Homomorphic(scheme = Scheme.PAILLIER, type = int.class)
                private String val;

                public AsyncEntity() {}
                public String getVal() { return val; }
                public void setVal(String v) { this.val = v; }
            }
            """;

        compile("AsyncEntity", source, genDir, classesDir);
        Path wrapper = genDir.resolve("com/example/apt/AsyncEntityBlindWrapper.java");
        String wrapperSrc = Files.readString(wrapper);
        
        assertTrue(wrapperSrc.contains("addValAsync(Ciphertext other)"), "Missing Async Add Ciphertext");
        assertTrue(wrapperSrc.contains("addValAsync(BigInteger plain)"), "Missing Async Add Plain");
        assertTrue(wrapperSrc.contains("subValAsync(Ciphertext other)"), "Missing Async Sub Ciphertext");
        assertTrue(wrapperSrc.contains("subValAsync(BigInteger plain)"), "Missing Async Sub Plain");
        assertTrue(wrapperSrc.contains("BlindAsync.runAsync"), "Async methods should use BlindAsync.runAsync");
        assertTrue(wrapperSrc.contains("BlindAsync.supplyAsync"), "Async methods should use BlindAsync.supplyAsync");
    }

    @Test
    public void arrayBatchingGeneratesCorrectSignatures(@TempDir Path tmpDir) throws Exception {
        Path genDir     = tmpDir.resolve("gen");
        Path classesDir = tmpDir.resolve("classes");
        Files.createDirectories(genDir);
        Files.createDirectories(classesDir);

        String source = """
            package com.example.apt;

            import se.deversity.blindbean.annotations.BlindEntity;
            import se.deversity.blindbean.annotations.Homomorphic;
            import se.deversity.blindbean.annotations.Scheme;

            @BlindEntity
            public class ArrayEntity {
                @Homomorphic(scheme = Scheme.BFV, type = long[].class)
                private String data;

                public ArrayEntity() {}
                public String getData() { return data; }
                public void setData(String d) { this.data = d; }
            }
            """;

        compile("ArrayEntity", source, genDir, classesDir);
        Path wrapper = genDir.resolve("com/example/apt/ArrayEntityBlindWrapper.java");
        String wrapperSrc = Files.readString(wrapper);
        
        assertTrue(wrapperSrc.contains("encryptData(long[] plain)"), "Missing long[] encryption");
        assertTrue(wrapperSrc.contains("long[] decryptData()"), "Missing long[] decryption");
        assertTrue(wrapperSrc.contains("addData(long[] plain)"), "Missing long[] plain math");
        assertTrue(wrapperSrc.contains("ctx.encryptLongArray(plain)"), "Should use encryptLongArray for batching");
    }

    @Test
    public void defaultMappingForFheSchemes(@TempDir Path tmpDir) throws Exception {
        Path genDir     = tmpDir.resolve("gen");
        Path classesDir = tmpDir.resolve("classes");
        Files.createDirectories(genDir);
        Files.createDirectories(classesDir);

        String source = """
            package com.example.apt;

            import se.deversity.blindbean.annotations.BlindEntity;
            import se.deversity.blindbean.annotations.Homomorphic;
            import se.deversity.blindbean.annotations.Scheme;

            @BlindEntity
            public class DefaultFheEntity {
                @Homomorphic(scheme = Scheme.BFV)
                private String bfvVal;
                @Homomorphic(scheme = Scheme.CKKS)
                private String ckksVal;

                public DefaultFheEntity() {}
                public String getBfvVal() { return bfvVal; }
                public void setBfvVal(String v) { this.bfvVal = v; }
                public String getCkksVal() { return ckksVal; }
                public void setCkksVal(String v) { this.ckksVal = v; }
            }
            """;

        compile("DefaultFheEntity", source, genDir, classesDir);
        Path wrapper = genDir.resolve("com/example/apt/DefaultFheEntityBlindWrapper.java");
        String wrapperSrc = Files.readString(wrapper);
        
        // BFV default should be long
        assertTrue(wrapperSrc.contains("encryptBfvVal(long plain)"), "BFV default should be long");
        assertTrue(wrapperSrc.contains("long decryptBfvVal()"), "BFV default should be long");

        // CKKS default should be double
        assertTrue(wrapperSrc.contains("encryptCkksVal(double plain)"), "CKKS default should be double");
        assertTrue(wrapperSrc.contains("double decryptCkksVal()"), "CKKS default should be double");
    }

    @Test
    public void unsupportedOperationsThrowErrors(@TempDir Path tmpDir) throws Exception {
        Path genDir     = tmpDir.resolve("gen");
        Path classesDir = tmpDir.resolve("classes");
        Files.createDirectories(genDir);
        Files.createDirectories(classesDir);

        String source = """
            package com.example.apt;

            import se.deversity.blindbean.annotations.BlindEntity;
            import se.deversity.blindbean.annotations.Homomorphic;
            import se.deversity.blindbean.annotations.Scheme;

            @BlindEntity
            public class UnsupportedEntity {
                @Homomorphic(scheme = Scheme.BFV, type = String.class)
                private String text;
                @Homomorphic(scheme = Scheme.PAILLIER, type = double.class)
                private String decimal;

                public UnsupportedEntity() {}
                public String getText() { return text; }
                public void setText(String t) { this.text = t; }
                public String getDecimal() { return decimal; }
                public void setDecimal(String d) { this.decimal = d; }
            }
            """;

        // Since Issue 4, unsupported type-scheme combinations are rejected at compile
        // time via APT errors rather than generating wrapper stubs that throw at runtime.
        List<Diagnostic<? extends JavaFileObject>> diags =
            compile("UnsupportedEntity", source, genDir, classesDir);

        // String type with a non-PAILLIER FHE scheme must produce an APT error
        // mentioning both "String" and the required "PAILLIER" scheme.
        boolean hasStringFheError = diags.stream()
            .filter(d -> d.getKind() == Diagnostic.Kind.ERROR)
            .anyMatch(d -> {
                String msg = d.getMessage(Locale.ROOT);
                return msg.contains("String") && msg.contains("PAILLIER");
            });

        // Floating-point type with a non-CKKS scheme must produce an APT error
        // mentioning the type family ("float"/"double") and the required "CKKS" scheme.
        boolean hasFloatSchemeError = diags.stream()
            .filter(d -> d.getKind() == Diagnostic.Kind.ERROR)
            .anyMatch(d -> {
                String msg = d.getMessage(Locale.ROOT);
                return (msg.contains("float") || msg.contains("double")) && msg.contains("CKKS");
            });

        assertTrue(hasStringFheError,
            "Expected APT error for String type with Scheme.BFV; diagnostics: " + diags);
        assertTrue(hasFloatSchemeError,
            "Expected APT error for double type with non-CKKS scheme; diagnostics: " + diags);
    }
}

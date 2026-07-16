package se.deversity.blindbean.processor;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;

import java.io.IOException;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Compile-time behaviour for the types added beyond the original scalar set.
 *
 * <p>These assert what the processor <em>generates</em> and what it <em>refuses</em>. The absence of
 * a method matters as much as its presence: a generated {@code addSeenAt(Instant)} would be an
 * invitation to add two dates together, and an {@code addBlob} would silently corrupt a blob.
 *
 * <p>They live here rather than in the example module because the processor runs at compile time —
 * exercising it through another module's javac tests the same code but instruments none of it.
 */
public class ExpandedTypeProcessorTest {

    private record Result(List<Diagnostic<? extends JavaFileObject>> diagnostics, String wrapper) {
        boolean failed() {
            return diagnostics.stream().anyMatch(d -> d.getKind() == Diagnostic.Kind.ERROR);
        }
        String errors() {
            return diagnostics.stream()
                .filter(d -> d.getKind() == Diagnostic.Kind.ERROR)
                .map(d -> d.getMessage(Locale.ROOT))
                .reduce("", (a, b) -> a + b + "\n");
        }
    }

    private Result compile(String className, String source, Path tmp) throws IOException {
        Path genDir = tmp.resolve("gen");
        Path classesDir = tmp.resolve("classes");
        Files.createDirectories(genDir);
        Files.createDirectories(classesDir);

        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        assertNotNull(compiler, "System Java compiler not available");

        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
        Path srcFile = tmp.resolve(className + ".java");
        Files.writeString(srcFile, source);

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
            "--add-modules", "jdk.incubator.vector");

        compiler.getTask(new StringWriter(), fm, diagnostics, options, null,
                         fm.getJavaFileObjects(srcFile.toFile())).call();
        fm.close();

        Path wrapper = genDir.resolve("com/example/apt/" + className + "BlindWrapper.java");
        String src = Files.exists(wrapper) ? Files.readString(wrapper) : "";
        return new Result(diagnostics.getDiagnostics(), src);
    }

    /** An entity with one @Homomorphic field of the given type. */
    private static String entity(String className, String annotation, String fieldName) {
        String cap = Character.toUpperCase(fieldName.charAt(0)) + fieldName.substring(1);
        return """
            package com.example.apt;
            import se.deversity.blindbean.annotations.*;
            @BlindEntity
            public class %s {
                %s
                private String %s;
                public %s() {}
                public String get%s() { return %s; }
                public void set%s(String v) { this.%s = v; }
            }
            """.formatted(className, annotation, fieldName, className, cap, fieldName, cap, fieldName);
    }

    // ── BigDecimal ───────────────────────────────────────────────────────────

    @Test
    public void bigDecimalBakesTheScaleAndAddsButCannotMultiply(@TempDir Path tmp) throws Exception {
        Result r = compile("Money", entity("Money",
            "@Homomorphic(scheme = Scheme.PAILLIER, type = java.math.BigDecimal.class, scale = 2)",
            "price"), tmp);

        assertFalse(r.failed(), r.errors());
        assertTrue(r.wrapper().contains("encryptPrice(java.math.BigDecimal plain)"));
        assertTrue(r.wrapper().contains("java.math.BigDecimal decryptPrice()"));
        assertTrue(r.wrapper().contains("setScale(2, java.math.RoundingMode.UNNECESSARY)"),
            "the scale must be baked in, and UNNECESSARY so a lost cent fails loudly");
        assertTrue(r.wrapper().contains("new java.math.BigDecimal(unscaled, 2)"));
        assertTrue(r.wrapper().contains("addPrice(java.math.BigDecimal plain)"));
        assertFalse(r.wrapper().contains("mulPrice"),
            "Paillier cannot multiply, so no mul may be offered");
        assertTrue(r.wrapper().contains("decryptSigned"),
            "a negative price must decode as negative, not as an n-sized residue");
    }

    @Test
    public void scaleOnANonDecimalFieldIsRejected(@TempDir Path tmp) throws Exception {
        Result r = compile("Bad", entity("Bad",
            "@Homomorphic(scheme = Scheme.PAILLIER, type = long.class, scale = 2)", "n"), tmp);

        assertTrue(r.failed());
        assertTrue(r.errors().contains("scale() only applies to BigDecimal"), r.errors());
    }

    @Test
    public void bigDecimalOnCkksIsRejected(@TempDir Path tmp) throws Exception {
        // CKKS *could* hold it, approximately — which is exactly why it must not be allowed to.
        Result r = compile("Approx", entity("Approx",
            "@Homomorphic(scheme = Scheme.CKKS, type = java.math.BigDecimal.class)", "price"), tmp);

        assertTrue(r.failed());
        assertTrue(r.errors().contains("PAILLIER"), r.errors());
    }

    // ── byte[] and java.time ─────────────────────────────────────────────────

    @Test
    public void byteArrayIsABlobWithNoArithmetic(@TempDir Path tmp) throws Exception {
        Result r = compile("Blobby", entity("Blobby",
            "@Homomorphic(scheme = Scheme.PAILLIER, type = byte[].class)", "blob"), tmp);

        assertFalse(r.failed(), r.errors());
        assertTrue(r.wrapper().contains("encryptBlob(byte[] plain)"));
        assertTrue(r.wrapper().contains("byte[] decryptBlob()"));
        assertFalse(r.wrapper().contains("addBlob"), "adding two blobs corrupts them");
        assertFalse(r.wrapper().contains("mulBlob"));
        // A blob is an unsigned magnitude: reading it signed would flip any blob whose top bit is set.
        assertFalse(r.wrapper().contains("decryptSigned"),
            "a blob must decode through the UNSIGNED path");
    }

    @Test
    public void pointsInTimeGetNoArithmeticButDurationsDo(@TempDir Path tmp) throws Exception {
        Result instant = compile("Seen", entity("Seen",
            "@Homomorphic(scheme = Scheme.PAILLIER, type = java.time.Instant.class)", "at"), tmp);
        assertFalse(instant.failed(), instant.errors());
        assertTrue(instant.wrapper().contains("java.time.Instant decryptAt()"));
        assertFalse(instant.wrapper().contains("addAt"),
            "Tuesday plus Thursday is not a date");

        Result date = compile("Born", entity("Born",
            "@Homomorphic(scheme = Scheme.PAILLIER, type = java.time.LocalDate.class)", "on"),
            tmp.resolve("b"));
        assertFalse(date.failed(), date.errors());
        assertTrue(date.wrapper().contains("toEpochDay"));
        assertFalse(date.wrapper().contains("addOn"));

        Result dur = compile("Up", entity("Up",
            "@Homomorphic(scheme = Scheme.PAILLIER, type = java.time.Duration.class)", "time"),
            tmp.resolve("d"));
        assertFalse(dur.failed(), dur.errors());
        assertTrue(dur.wrapper().contains("addTime(java.time.Duration plain)"),
            "a Duration is a quantity — it adds");
        assertTrue(dur.wrapper().contains("subTime(java.time.Duration plain)"));
    }

    @Test
    public void temporalOnBfvIsRejected(@TempDir Path tmp) throws Exception {
        Result r = compile("T", entity("T",
            "@Homomorphic(scheme = Scheme.BFV, type = java.time.Instant.class)", "at"), tmp);
        assertTrue(r.failed());
        assertTrue(r.errors().contains("PAILLIER"), r.errors());
    }

    // ── Vectors ──────────────────────────────────────────────────────────────

    @Test
    public void intVectorsWidenToBfvSlots(@TempDir Path tmp) throws Exception {
        Result r = compile("Counters", entity("Counters",
            "@Homomorphic(scheme = Scheme.BFV, type = int[].class)", "counts"), tmp);

        assertFalse(r.failed(), r.errors());
        assertTrue(r.wrapper().contains("encryptCounts(int[] plain)"));
        assertTrue(r.wrapper().contains("int[] decryptCounts()"));
        assertTrue(r.wrapper().contains("long[] slots = new long[plain.length]"),
            "an int[] must be widened to the long[] the bridge takes");
        assertTrue(r.wrapper().contains("ctx.encryptLongArray(slots)"));
        assertTrue(r.wrapper().contains("mulCounts(int[] plain)"), "BFV multiplies");
    }

    @Test
    public void longVectorsArePassedStraightThroughWithNoPointlessCopy(@TempDir Path tmp) throws Exception {
        Result r = compile("Raw", entity("Raw",
            "@Homomorphic(scheme = Scheme.BFV, type = long[].class)", "data"), tmp);

        assertFalse(r.failed(), r.errors());
        assertTrue(r.wrapper().contains("ctx.encryptLongArray(plain)"),
            "a long[] IS the slot type — copying it into a local would be waste");
        assertFalse(r.wrapper().contains("long[] slots = new long[plain.length]"));
    }

    @Test
    public void doubleAndFloatVectorsGoToCkks(@TempDir Path tmp) throws Exception {
        Result d = compile("Signal", entity("Signal",
            "@Homomorphic(scheme = Scheme.CKKS, type = double[].class)", "wave"), tmp);
        assertFalse(d.failed(), d.errors());
        assertTrue(d.wrapper().contains("ctx.encryptDoubleArray(plain)"));
        assertTrue(d.wrapper().contains("double[] decryptWave()"));
        assertTrue(d.wrapper().contains("mulWave(double[] plain)"));

        Result f = compile("Weights", entity("Weights",
            "@Homomorphic(scheme = Scheme.CKKS, type = float[].class)", "w"), tmp.resolve("f"));
        assertFalse(f.failed(), f.errors());
        assertTrue(f.wrapper().contains("double[] slots = new double[plain.length]"),
            "a float[] must be widened to the double[] the bridge takes");
    }

    @Test
    public void aRealVectorOnBfvIsRejected(@TempDir Path tmp) throws Exception {
        Result r = compile("Wrong", entity("Wrong",
            "@Homomorphic(scheme = Scheme.BFV, type = double[].class)", "v"), tmp);
        assertTrue(r.failed());
        assertTrue(r.errors().contains("CKKS"), r.errors());
    }

    @Test
    public void anIntegerVectorOnCkksIsRejected(@TempDir Path tmp) throws Exception {
        Result r = compile("Wrong2", entity("Wrong2",
            "@Homomorphic(scheme = Scheme.CKKS, type = int[].class)", "v"), tmp);
        assertTrue(r.failed());
        assertTrue(r.errors().contains("BFV"), r.errors());
    }

    // ── Nullability ──────────────────────────────────────────────────────────

    @Test
    public void aBoxedScalarDecryptsToNullButStillEncryptsAPrimitive(@TempDir Path tmp) throws Exception {
        // Boxed scalars take the PRIMITIVE on the way in — an established choice in this processor.
        // So they are nullable outbound (a null column decrypts to null) but not inbound; to store
        // a null you set the entity's field to null yourself.
        Result boxed = compile("Boxed", entity("Boxed",
            "@Homomorphic(scheme = Scheme.PAILLIER, type = Long.class)", "count"), tmp);

        assertFalse(boxed.failed(), boxed.errors());
        assertTrue(boxed.wrapper().contains("encryptCount(long plain)"),
            "boxed scalars take the primitive in");
        assertTrue(boxed.wrapper().contains("Long decryptCount()"));
        assertTrue(boxed.wrapper().contains("if (entity.getCount() == null) return null;"),
            "a null column must decrypt to null, not blow up on an empty hex string");
    }

    @Test
    public void aBoxedBooleanGeneratesCompilableCodeAndDecryptsToNull(@TempDir Path tmp) throws Exception {
        // Boxed Boolean is a supported boxed scalar (isNullable treats it as one), so like Long it
        // must decrypt to null for a null column — which requires the generated decrypt method to
        // return Boolean, not the primitive. A primitive return with a null guard does not even
        // compile, so the wrapper for any entity with a Boolean field failed the consumer's build.
        Result r = compile("Flag", entity("Flag",
            "@Homomorphic(scheme = Scheme.PAILLIER, type = Boolean.class)", "active"), tmp);

        assertFalse(r.failed(), r.errors());
        assertTrue(r.wrapper().contains("Boolean decryptActive()"),
            "a boxed Boolean must decrypt to the boxed type so a null column can decrypt to null");
        assertTrue(r.wrapper().contains("if (entity.getActive() == null) return null;"));
        assertTrue(r.wrapper().contains("encryptActive(boolean plain)"),
            "boxed scalars take the primitive in — the established choice for every other boxed type");
        assertFalse(r.wrapper().contains("addActive"), "no arithmetic on booleans");
    }

    @Test
    public void aPrimitiveBooleanKeepsThePrimitiveSignatureAndNoNullGuard(@TempDir Path tmp) throws Exception {
        Result r = compile("PFlag", entity("PFlag",
            "@Homomorphic(scheme = Scheme.PAILLIER, type = boolean.class)", "active"), tmp);

        assertFalse(r.failed(), r.errors());
        assertTrue(r.wrapper().contains("boolean decryptActive()"));
        assertFalse(r.wrapper().contains("return null;"),
            "a primitive boolean cannot be null — a guard there would not compile");
    }

    @Test
    public void aReferenceTypeAcceptsNullOnBothSides(@TempDir Path tmp) throws Exception {
        Result r = compile("Ref", entity("Ref",
            "@Homomorphic(scheme = Scheme.PAILLIER, type = java.math.BigDecimal.class, scale = 2)",
            "price"), tmp);

        assertFalse(r.failed(), r.errors());
        assertTrue(r.wrapper().contains("if (plain == null) { entity.setPrice(null); return; }"),
            "encrypting null must write null, not an encryption of zero");
        assertTrue(r.wrapper().contains("if (entity.getPrice() == null) return null;"));
    }

    @Test
    public void aPrimitiveGetsNoNullGuard(@TempDir Path tmp) throws Exception {
        Result prim = compile("Prim", entity("Prim",
            "@Homomorphic(scheme = Scheme.PAILLIER, type = long.class)", "count"), tmp);

        assertFalse(prim.failed(), prim.errors());
        assertFalse(prim.wrapper().contains("return null;"),
            "a primitive cannot be null — a guard there would not even compile");
    }

    // ── Nested entities ──────────────────────────────────────────────────────

    /** Two entities in one compilation unit: an outer one nesting an inner one. */
    private static String nestedPair(String outerAnnotation) {
        return """
            package com.example.apt;
            import se.deversity.blindbean.annotations.*;
            @BlindEntity
            class Inner {
                @Homomorphic(scheme = Scheme.PAILLIER, type = long.class)
                private String secret;
                public Inner() {}
                public String getSecret() { return secret; }
                public void setSecret(String v) { this.secret = v; }
            }
            @BlindEntity
            public class Outer {
                %s
                private Inner inner;
                public Outer() {}
                public Inner getInner() { return inner; }
                public void setInner(Inner v) { this.inner = v; }
            }
            """.formatted(outerAnnotation);
    }

    @Test
    public void aNestedEntityGetsAnAccessorIntoItsOwnWrapper(@TempDir Path tmp) throws Exception {
        Result r = compile("Outer", nestedPair("@BlindNested"), tmp);

        assertFalse(r.failed(), r.errors());
        assertTrue(r.wrapper().contains("InnerBlindWrapper inner()"),
            "the accessor must hand back the nested entity's own wrapper");
        assertTrue(r.wrapper().contains("return inner == null ? null : new"),
            "a null nested entity must yield a null wrapper, not an NPE several frames deep");
    }

    @Test
    public void nestingSomethingThatIsNotAnEntityIsRejected(@TempDir Path tmp) throws Exception {
        String src = """
            package com.example.apt;
            import se.deversity.blindbean.annotations.*;
            @BlindEntity
            public class Outer {
                @BlindNested
                private String notAnEntity;
                public Outer() {}
                public String getNotAnEntity() { return notAnEntity; }
                public void setNotAnEntity(String v) { this.notAnEntity = v; }
            }
            """;
        Result r = compile("Outer", src, tmp);

        // Without this, the failure would surface as "cannot find symbol StringBlindWrapper" in
        // generated code the author never wrote.
        assertTrue(r.failed());
        assertTrue(r.errors().contains("not a @BlindEntity"), r.errors());
    }

    @Test
    public void aFieldCannotBeBothEncryptedAndNested(@TempDir Path tmp) throws Exception {
        // The field is a String, so it passes the "@Homomorphic must be a String" check and
        // actually reaches the both-annotations guard. (When the field is typed as the nested
        // entity instead, the String check fires first — see the next test.)
        Result r = compile("Outer", entity("Outer",
            "@BlindNested\n    @Homomorphic(scheme = Scheme.PAILLIER)", "thing"), tmp);

        assertTrue(r.failed());
        assertTrue(r.errors().contains("either an encrypted value or a nested entity"), r.errors());
    }

    @Test
    public void anEntityTypedFieldMarkedEncryptedIsCaughtByTheStringRule(@TempDir Path tmp) throws Exception {
        Result r = compile("Outer",
            nestedPair("@BlindNested\n    @Homomorphic(scheme = Scheme.PAILLIER)"), tmp);

        assertTrue(r.failed());
        assertTrue(r.errors().contains("must be of type String"), r.errors());
    }

    // ── Records ──────────────────────────────────────────────────────────────

    @Test
    public void aRecordIsRefusedWithAReasonNotJustARejection(@TempDir Path tmp) throws Exception {
        String src = """
            package com.example.apt;
            import se.deversity.blindbean.annotations.*;
            @BlindEntity
            public record Rec(String balance) {}
            """;
        Result r = compile("Rec", src, tmp);

        assertTrue(r.failed());
        // The wrapper stores each ciphertext with setX(...); a record's components are final.
        // Saying so is the difference between a fixable error and a baffling one.
        assertTrue(r.errors().contains("record"), r.errors());
        assertTrue(r.errors().contains("final"), r.errors());
    }
}

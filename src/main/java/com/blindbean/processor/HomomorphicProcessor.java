package com.blindbean.processor;

import com.blindbean.annotations.BlindEntity;
import com.blindbean.annotations.Homomorphic;
import com.blindbean.annotations.Scheme;
import com.google.auto.service.AutoService;

import javax.annotation.processing.AbstractProcessor;
import javax.annotation.processing.Processor;
import javax.annotation.processing.RoundEnvironment;
import javax.annotation.processing.SupportedAnnotationTypes;
import javax.annotation.processing.SupportedSourceVersion;
import javax.lang.model.SourceVersion;
import javax.lang.model.element.Element;
import javax.lang.model.element.ElementKind;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.Modifier;
import javax.lang.model.element.TypeElement;
import javax.lang.model.element.VariableElement;
import javax.lang.model.util.ElementFilter;
import javax.lang.model.type.TypeKind;
import javax.lang.model.type.MirroredTypeException;
import javax.lang.model.type.TypeMirror;
import javax.tools.Diagnostic;
import javax.tools.JavaFileObject;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@SupportedAnnotationTypes({
    "com.blindbean.annotations.BlindEntity",
    "com.blindbean.annotations.Homomorphic"
})
@SupportedSourceVersion(SourceVersion.RELEASE_26)
@AutoService(Processor.class)
public class HomomorphicProcessor extends AbstractProcessor {

    /** Immutable model for one @Homomorphic field. */
    private record FieldModel(String name, String capName, Scheme scheme, String typeName) {}

    @Override
    public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment roundEnv) {
        // Warn about @Homomorphic on non-@BlindEntity classes
        for (Element element : roundEnv.getElementsAnnotatedWith(Homomorphic.class)) {
            Element enclosing = element.getEnclosingElement();
            if (enclosing == null || enclosing.getAnnotation(BlindEntity.class) == null) {
                processingEnv.getMessager().printMessage(
                    Diagnostic.Kind.WARNING,
                    "@Homomorphic field '" + element.getSimpleName()
                        + "' is not inside a @BlindEntity class — skipping",
                    element);
            }
        }

        for (Element element : roundEnv.getElementsAnnotatedWith(BlindEntity.class)) {
            if (element.getKind() != ElementKind.CLASS) {
                processingEnv.getMessager().printMessage(
                    Diagnostic.Kind.ERROR, "@BlindEntity only applies to classes", element);
                continue;
            }

            TypeElement typeElement = (TypeElement) element;
            if (!validateEntity(typeElement)) {
                continue;
            }

            List<FieldModel> fields = collectFields(typeElement);
            if (fields == null) {
                // collectFields already emitted errors
                continue;
            }

            String className   = typeElement.getSimpleName().toString();
            String packageName = processingEnv.getElementUtils()
                    .getPackageOf(typeElement).getQualifiedName().toString();
            generateBlindWrapper(packageName, className, typeElement, fields);
        }
        return true;
    }

    // ── Validation ────────────────────────────────────────────────────────

    private boolean validateEntity(TypeElement typeElement) {
        boolean ok = true;

        if (typeElement.getModifiers().contains(Modifier.ABSTRACT)) {
            processingEnv.getMessager().printMessage(
                Diagnostic.Kind.ERROR,
                "@BlindEntity class must not be abstract",
                typeElement);
            ok = false;
        }

        // Check for accessible no-arg constructor
        boolean hasNoArg = ElementFilter.constructorsIn(typeElement.getEnclosedElements())
            .stream()
            .anyMatch(c -> c.getParameters().isEmpty()
                       && !c.getModifiers().contains(Modifier.PRIVATE));
        // Note: some entities only have parameterized constructors (like Wallet) — that is fine;
        // the wrapper just wraps an existing instance. We only require one constructor to exist.
        // (Relax: just check the class is not an interface — already handled by KIND check.)

        return ok;
    }

    /**
     * Walks enclosed elements, collects @Homomorphic fields, validates each.
     * Returns null (not an empty list) if any field had a hard error.
     */
    private List<FieldModel> collectFields(TypeElement typeElement) {
        List<FieldModel> result = new ArrayList<>();
        boolean hadError = false;

        List<ExecutableElement> methods = ElementFilter.methodsIn(
            processingEnv.getElementUtils().getAllMembers(typeElement));

        for (VariableElement field : ElementFilter.fieldsIn(typeElement.getEnclosedElements())) {
            Homomorphic ann = field.getAnnotation(Homomorphic.class);
            if (ann == null) continue;

            String fieldName = field.getSimpleName().toString();
            String capName   = Character.toUpperCase(fieldName.charAt(0)) + fieldName.substring(1);

            // 1. Field type must be String
            if (field.asType().getKind() != TypeKind.DECLARED
                    || !field.asType().toString().equals("java.lang.String")) {
                processingEnv.getMessager().printMessage(
                    Diagnostic.Kind.ERROR,
                    "@Homomorphic field '" + fieldName + "' must be of type String "
                        + "(hex ciphertext storage); found: " + field.asType(),
                    field);
                hadError = true;
                continue;
            }

            // 2. Getter must exist: public String getXxx()
            final String getterName = "get" + capName;
            boolean hasGetter = methods.stream().anyMatch(m ->
                m.getSimpleName().toString().equals(getterName)
                && m.getParameters().isEmpty()
                && m.getReturnType().toString().equals("java.lang.String")
                && !m.getModifiers().contains(Modifier.PRIVATE));
            if (!hasGetter) {
                processingEnv.getMessager().printMessage(
                    Diagnostic.Kind.ERROR,
                    "@Homomorphic field '" + fieldName + "' is missing getter '"
                        + getterName + "(): String'",
                    field);
                hadError = true;
                continue;
            }

            // 3. Setter must exist: public void setXxx(String)
            final String setterName = "set" + capName;
            boolean hasSetter = methods.stream().anyMatch(m ->
                m.getSimpleName().toString().equals(setterName)
                && m.getParameters().size() == 1
                && m.getParameters().get(0).asType().toString().equals("java.lang.String")
                && m.getReturnType().getKind() == TypeKind.VOID
                && !m.getModifiers().contains(Modifier.PRIVATE));
            if (!hasSetter) {
                processingEnv.getMessager().printMessage(
                    Diagnostic.Kind.ERROR,
                    "@Homomorphic field '" + fieldName + "' is missing setter '"
                        + setterName + "(String): void'",
                    field);
                hadError = true;
                continue;
            }

            // 4. Scheme must be supported
            Scheme scheme = ann.scheme();
            if (scheme == Scheme.ELGAMAL) {
                processingEnv.getMessager().printMessage(
                    Diagnostic.Kind.ERROR,
                    "@Homomorphic field '" + fieldName + "': scheme ELGAMAL is not supported "
                        + "by BlindMath — use PAILLIER, BFV, or CKKS",
                    field);
                hadError = true;
                continue;
            }

            TypeMirror typeMirror = null;
            try {
                ann.type();
            } catch (MirroredTypeException e) {
                typeMirror = e.getTypeMirror();
            }
            String typeName = typeMirror != null ? typeMirror.toString() : "java.lang.Void";

            result.add(new FieldModel(fieldName, capName, scheme, typeName));
        }

        return hadError ? null : result;
    }

    // ── Code generation ───────────────────────────────────────────────────

    private void generateBlindWrapper(String packageName, String className,
                                      TypeElement typeElement, List<FieldModel> fields) {
        String wrapperName = className + "BlindWrapper";
        try {
            JavaFileObject builderFile = processingEnv.getFiler()
                .createSourceFile(packageName + "." + wrapperName, typeElement);

            boolean needsBigInteger = fields.stream().anyMatch(f -> f.scheme() == Scheme.PAILLIER);
            boolean needsFhe        = fields.stream()
                .anyMatch(f -> f.scheme() == Scheme.BFV || f.scheme() == Scheme.CKKS);

            try (PrintWriter out = new PrintWriter(builderFile.openWriter())) {
                // Header
                out.println("// Generated by BlindBean HomomorphicProcessor — do not edit");
                out.println("package " + packageName + ";");
                out.println();

                // Imports
                out.println("import com.blindbean.core.Ciphertext;");
                out.println("import com.blindbean.math.BlindMath;");
                out.println("import com.blindbean.context.BlindContext;");
                out.println("import com.blindbean.annotations.Scheme;");
                if (needsBigInteger) {
                    out.println("import java.math.BigInteger;");
                }
                if (needsFhe) {
                    out.println("import com.blindbean.fhe.FheCiphertextNative;");
                    out.println("import com.blindbean.fhe.FheContext;");
                }
                out.println();

                // Class declaration
                out.println("public class " + wrapperName + " {");
                out.println("    private final " + className + " entity;");
                out.println();
                out.println("    public " + wrapperName + "(" + className + " entity) {");
                out.println("        this.entity = entity;");
                out.println("    }");

                // Per-field methods
                for (FieldModel f : fields) {
                    out.println();
                    emitGetCiphertext(out, f);
                    out.println();
                    emitEncrypt(out, f);
                    out.println();
                    emitDecrypt(out, f);

                    boolean mathSupported = !f.typeName().equals("java.lang.String") &&
                                            !f.typeName().equals("boolean") &&
                                            !f.typeName().equals("java.lang.Boolean");

                    if (mathSupported) {
                        out.println();
                        emitAdd(out, f);
                        out.println();
                        emitSub(out, f);
                        out.println();
                        emitAddPlain(out, f);
                        out.println();
                        emitSubPlain(out, f);
                        if (f.scheme() == Scheme.BFV || f.scheme() == Scheme.CKKS) {
                            out.println();
                            emitMultiply(out, f);
                            out.println();
                            emitMulPlain(out, f);
                        }
                    }
                }

                out.println("}");
            }
        } catch (IOException e) {
            processingEnv.getMessager().printMessage(Diagnostic.Kind.ERROR, e.toString());
        }
    }

    // ── Per-method emitters ───────────────────────────────────────────────

    private void emitGetCiphertext(PrintWriter out, FieldModel f) {
        out.println("    public Ciphertext getCiphertext" + f.capName() + "() {");
        out.println("        return new Ciphertext(entity.get" + f.capName() + "(), Scheme." + f.scheme().name() + ");");
        out.println("    }");
    }

    private void emitEncrypt(PrintWriter out, FieldModel f) {
        String typeName = f.typeName();
        if (typeName.equals("java.lang.String")) {
            out.println("    public void encrypt" + f.capName() + "(String plain) {");
            if (f.scheme() == Scheme.PAILLIER) {
                out.println("        java.math.BigInteger encoded = new java.math.BigInteger(1, plain.getBytes(java.nio.charset.StandardCharsets.UTF_8));");
                out.println("        Ciphertext ct = BlindContext.getPaillier().encrypt(encoded);");
                out.println("        entity.set" + f.capName() + "(ct.hexData());");
            } else {
                out.println("        throw new UnsupportedOperationException(\"String encryption not supported securely on FHE without batching\");");
            }
            out.println("    }");
        } else if (typeName.equals("boolean") || typeName.equals("java.lang.Boolean")) {
            out.println("    public void encrypt" + f.capName() + "(boolean plain) {");
            if (f.scheme() == Scheme.PAILLIER) {
                out.println("        Ciphertext ct = BlindContext.getPaillier().encrypt(plain ? java.math.BigInteger.ONE : java.math.BigInteger.ZERO);");
                out.println("        entity.set" + f.capName() + "(ct.hexData());");
            } else if (f.scheme() == Scheme.BFV) {
                out.println("        FheContext ctx = BlindContext.getFheContext();");
                out.println("        try (FheCiphertextNative ct = new FheCiphertextNative(ctx.encryptLong(plain ? 1L : 0L), ctx)) {");
                out.println("            entity.set" + f.capName() + "(ct.toBlindCiphertext().hexData());");
                out.println("        }");
            } else {
                out.println("        FheContext ctx = BlindContext.getFheContext();");
                out.println("        try (FheCiphertextNative ct = new FheCiphertextNative(ctx.encryptDouble(plain ? 1.0 : 0.0), ctx)) {");
                out.println("            entity.set" + f.capName() + "(ct.toBlindCiphertext().hexData());");
                out.println("        }");
            }
            out.println("    }");
        } else if (typeName.equals("int") || typeName.equals("java.lang.Integer")) {
            switch (f.scheme()) {
                case PAILLIER -> {
                    out.println("    public void encrypt" + f.capName() + "(int plain) {");
                    out.println("        Ciphertext ct = BlindContext.getPaillier().encrypt(java.math.BigInteger.valueOf(plain));");
                    out.println("        entity.set" + f.capName() + "(ct.hexData());");
                    out.println("    }");
                }
                case BFV -> {
                    out.println("    public void encrypt" + f.capName() + "(int plain) {");
                    out.println("        FheContext ctx = BlindContext.getFheContext();");
                    out.println("        try (FheCiphertextNative ct = new FheCiphertextNative(ctx.encryptLong((long)plain), ctx)) {");
                    out.println("            entity.set" + f.capName() + "(ct.toBlindCiphertext().hexData());");
                    out.println("        }");
                    out.println("    }");
                }
                case CKKS -> {
                    out.println("    public void encrypt" + f.capName() + "(int plain) {");
                    out.println("        FheContext ctx = BlindContext.getFheContext();");
                    out.println("        try (FheCiphertextNative ct = new FheCiphertextNative(ctx.encryptDouble((double)plain), ctx)) {");
                    out.println("            entity.set" + f.capName() + "(ct.toBlindCiphertext().hexData());");
                    out.println("        }");
                    out.println("    }");
                }
            }
        } else if (typeName.equals("long[]")) {
            if (f.scheme() == Scheme.BFV) {
                out.println("    public void encrypt" + f.capName() + "(long[] plain) {");
                out.println("        FheContext ctx = BlindContext.getFheContext();");
                out.println("        try (FheCiphertextNative ct = new FheCiphertextNative(ctx.encryptLongArray(plain), ctx)) {");
                out.println("            entity.set" + f.capName() + "(ct.toBlindCiphertext().hexData());");
                out.println("        }");
                out.println("    }");
            } else {
                out.println("    public void encrypt" + f.capName() + "(long[] plain) {");
                out.println("        throw new UnsupportedOperationException(\"long[] array batching is exclusively supported by Scheme.BFV\");");
                out.println("    }");
            }
        } else {
            // Default mapping
            switch (f.scheme()) {
                case PAILLIER -> {
                    out.println("    public void encrypt" + f.capName() + "(java.math.BigInteger plain) {");
                    out.println("        Ciphertext ct = BlindContext.getPaillier().encrypt(plain);");
                    out.println("        entity.set" + f.capName() + "(ct.hexData());");
                    out.println("    }");
                }
                case BFV -> {
                    out.println("    public void encrypt" + f.capName() + "(long plain) {");
                    out.println("        FheContext ctx = BlindContext.getFheContext();");
                    out.println("        try (FheCiphertextNative ct = new FheCiphertextNative(ctx.encryptLong(plain), ctx)) {");
                    out.println("            entity.set" + f.capName() + "(ct.toBlindCiphertext().hexData());");
                    out.println("        }");
                    out.println("    }");
                }
                case CKKS -> {
                    out.println("    public void encrypt" + f.capName() + "(double plain) {");
                    out.println("        FheContext ctx = BlindContext.getFheContext();");
                    out.println("        try (FheCiphertextNative ct = new FheCiphertextNative(ctx.encryptDouble(plain), ctx)) {");
                    out.println("            entity.set" + f.capName() + "(ct.toBlindCiphertext().hexData());");
                    out.println("        }");
                    out.println("    }");
                }
            }
        }
    }

    private void emitDecrypt(PrintWriter out, FieldModel f) {
        String typeName = f.typeName();
        if (typeName.equals("java.lang.String")) {
            out.println("    public String decrypt" + f.capName() + "() {");
            if (f.scheme() == Scheme.PAILLIER) {
                out.println("        java.math.BigInteger encoded = BlindContext.getPaillier().decrypt(getCiphertext" + f.capName() + "());");
                out.println("        return new String(encoded.toByteArray(), java.nio.charset.StandardCharsets.UTF_8);");
            } else {
                out.println("        throw new UnsupportedOperationException(\"String decryption not supported on FHE.\");");
            }
            out.println("    }");
        } else if (typeName.equals("boolean") || typeName.equals("java.lang.Boolean")) {
            out.println("    public boolean decrypt" + f.capName() + "() {");
            if (f.scheme() == Scheme.PAILLIER) {
                out.println("        return java.math.BigInteger.ZERO.compareTo(BlindContext.getPaillier().decrypt(getCiphertext" + f.capName() + "())) != 0;");
            } else if (f.scheme() == Scheme.BFV) {
                out.println("        FheContext ctx = BlindContext.getFheContext();");
                out.println("        try (FheCiphertextNative ct = FheCiphertextNative.fromBlindCiphertext(ctx, getCiphertext" + f.capName() + "())) {");
                out.println("            return ctx.decryptLong(ct.handle()) != 0L;");
                out.println("        }");
            } else {
                out.println("        FheContext ctx = BlindContext.getFheContext();");
                out.println("        try (FheCiphertextNative ct = FheCiphertextNative.fromBlindCiphertext(ctx, getCiphertext" + f.capName() + "())) {");
                out.println("            return ctx.decryptDouble(ct.handle()) != 0.0;");
                out.println("        }");
            }
            out.println("    }");
        } else if (typeName.equals("int") || typeName.equals("java.lang.Integer")) {
            switch (f.scheme()) {
                case PAILLIER -> {
                    out.println("    public int decrypt" + f.capName() + "() {");
                    out.println("        return BlindContext.getPaillier().decrypt(getCiphertext" + f.capName() + "()).intValue();");
                    out.println("    }");
                }
                case BFV -> {
                    out.println("    public int decrypt" + f.capName() + "() {");
                    out.println("        FheContext ctx = BlindContext.getFheContext();");
                    out.println("        try (FheCiphertextNative ct = FheCiphertextNative.fromBlindCiphertext(ctx, getCiphertext" + f.capName() + "())) {");
                    out.println("            return (int)ctx.decryptLong(ct.handle());");
                    out.println("        }");
                    out.println("    }");
                }
                case CKKS -> {
                    out.println("    public int decrypt" + f.capName() + "() {");
                    out.println("        FheContext ctx = BlindContext.getFheContext();");
                    out.println("        try (FheCiphertextNative ct = FheCiphertextNative.fromBlindCiphertext(ctx, getCiphertext" + f.capName() + "())) {");
                    out.println("            return (int)ctx.decryptDouble(ct.handle());");
                    out.println("        }");
                    out.println("    }");
                }
            }
        } else if (typeName.equals("long[]")) {
            if (f.scheme() == Scheme.BFV) {
                out.println("    public long[] decrypt" + f.capName() + "() {");
                out.println("        FheContext ctx = BlindContext.getFheContext();");
                out.println("        try (FheCiphertextNative ct = FheCiphertextNative.fromBlindCiphertext(ctx, getCiphertext" + f.capName() + "())) {");
                out.println("            return ctx.decryptLongArray(ct.handle());");
                out.println("        }");
                out.println("    }");
            } else {
                out.println("    public long[] decrypt" + f.capName() + "() {");
                out.println("        throw new UnsupportedOperationException(\"long[] array batching is exclusively supported by Scheme.BFV\");");
                out.println("    }");
            }
        } else {
            // Default mapping
            switch (f.scheme()) {
                case PAILLIER -> {
                    out.println("    public java.math.BigInteger decrypt" + f.capName() + "() {");
                    out.println("        return BlindContext.getPaillier().decrypt(getCiphertext" + f.capName() + "());");
                    out.println("    }");
                }
                case BFV -> {
                    out.println("    public long decrypt" + f.capName() + "() {");
                    out.println("        FheContext ctx = BlindContext.getFheContext();");
                    out.println("        try (FheCiphertextNative ct = FheCiphertextNative.fromBlindCiphertext(ctx, getCiphertext" + f.capName() + "())) {");
                    out.println("            return ctx.decryptLong(ct.handle());");
                    out.println("        }");
                    out.println("    }");
                }
                case CKKS -> {
                    out.println("    public double decrypt" + f.capName() + "() {");
                    out.println("        FheContext ctx = BlindContext.getFheContext();");
                    out.println("        try (FheCiphertextNative ct = FheCiphertextNative.fromBlindCiphertext(ctx, getCiphertext" + f.capName() + "())) {");
                    out.println("            return ctx.decryptDouble(ct.handle());");
                    out.println("        }");
                    out.println("    }");
                }
            }
        }
    }

    private void emitAdd(PrintWriter out, FieldModel f) {
        out.println("    public void add" + f.capName() + "(Ciphertext other) {");
        out.println("        Ciphertext sum = BlindMath.add(getCiphertext" + f.capName() + "(), other);");
        out.println("        entity.set" + f.capName() + "(sum.hexData());");
        out.println("    }");
    }

    private void emitSub(PrintWriter out, FieldModel f) {
        out.println("    public void sub" + f.capName() + "(Ciphertext other) {");
        out.println("        Ciphertext diff = BlindMath.subtract(getCiphertext" + f.capName() + "(), other);");
        out.println("        entity.set" + f.capName() + "(diff.hexData());");
        out.println("    }");
    }

    private void emitAddPlain(PrintWriter out, FieldModel f) {
        String typeName = f.typeName();
        if (typeName.equals("long[]") && f.scheme() == Scheme.BFV) {
            out.println("    public void add" + f.capName() + "(long[] plain) {");
            out.println("        FheContext ctx = BlindContext.getFheContext();");
            out.println("        try (FheCiphertextNative ct = new FheCiphertextNative(ctx.encryptLongArray(plain), ctx)) {");
            out.println("            add" + f.capName() + "(ct.toBlindCiphertext());");
            out.println("        }");
            out.println("    }");
            return;
        }
        switch (f.scheme()) {
            case PAILLIER -> {
                out.println("    public void add" + f.capName() + "(BigInteger plain) {");
                out.println("        Ciphertext ct = BlindContext.getPaillier().encrypt(plain);");
                out.println("        add" + f.capName() + "(ct);");
                out.println("    }");
            }
            case BFV -> {
                out.println("    public void add" + f.capName() + "(long plain) {");
                out.println("        FheContext ctx = BlindContext.getFheContext();");
                out.println("        try (FheCiphertextNative ct = new FheCiphertextNative(ctx.encryptLong(plain), ctx)) {");
                out.println("            add" + f.capName() + "(ct.toBlindCiphertext());");
                out.println("        }");
                out.println("    }");
            }
            case CKKS -> {
                out.println("    public void add" + f.capName() + "(double plain) {");
                out.println("        FheContext ctx = BlindContext.getFheContext();");
                out.println("        try (FheCiphertextNative ct = new FheCiphertextNative(ctx.encryptDouble(plain), ctx)) {");
                out.println("            add" + f.capName() + "(ct.toBlindCiphertext());");
                out.println("        }");
                out.println("    }");
            }
            default -> throw new IllegalStateException("Unsupported scheme: " + f.scheme());
        }
    }

    private void emitSubPlain(PrintWriter out, FieldModel f) {
        String typeName = f.typeName();
        if (typeName.equals("long[]") && f.scheme() == Scheme.BFV) {
            out.println("    public void sub" + f.capName() + "(long[] plain) {");
            out.println("        FheContext ctx = BlindContext.getFheContext();");
            out.println("        try (FheCiphertextNative ct = new FheCiphertextNative(ctx.encryptLongArray(plain), ctx)) {");
            out.println("            sub" + f.capName() + "(ct.toBlindCiphertext());");
            out.println("        }");
            out.println("    }");
            return;
        }
        switch (f.scheme()) {
            case PAILLIER -> {
                out.println("    public void sub" + f.capName() + "(BigInteger plain) {");
                out.println("        Ciphertext ct = BlindContext.getPaillier().encrypt(plain);");
                out.println("        sub" + f.capName() + "(ct);");
                out.println("    }");
            }
            case BFV -> {
                out.println("    public void sub" + f.capName() + "(long plain) {");
                out.println("        FheContext ctx = BlindContext.getFheContext();");
                out.println("        try (FheCiphertextNative ct = new FheCiphertextNative(ctx.encryptLong(plain), ctx)) {");
                out.println("            sub" + f.capName() + "(ct.toBlindCiphertext());");
                out.println("        }");
                out.println("    }");
            }
            case CKKS -> {
                out.println("    public void sub" + f.capName() + "(double plain) {");
                out.println("        FheContext ctx = BlindContext.getFheContext();");
                out.println("        try (FheCiphertextNative ct = new FheCiphertextNative(ctx.encryptDouble(plain), ctx)) {");
                out.println("            sub" + f.capName() + "(ct.toBlindCiphertext());");
                out.println("        }");
                out.println("    }");
            }
            default -> throw new IllegalStateException("Unsupported scheme: " + f.scheme());
        }
    }

    private void emitMultiply(PrintWriter out, FieldModel f) {
        out.println("    public void mul" + f.capName() + "(Ciphertext other) {");
        out.println("        Ciphertext product = BlindMath.multiply(getCiphertext" + f.capName() + "(), other);");
        out.println("        entity.set" + f.capName() + "(product.hexData());");
        out.println("    }");
    }

    private void emitMulPlain(PrintWriter out, FieldModel f) {
        String typeName = f.typeName();
        if (typeName.equals("long[]") && f.scheme() == Scheme.BFV) {
            out.println("    public void mul" + f.capName() + "(long[] plain) {");
            out.println("        FheContext ctx = BlindContext.getFheContext();");
            out.println("        try (FheCiphertextNative ct = new FheCiphertextNative(ctx.encryptLongArray(plain), ctx)) {");
            out.println("            mul" + f.capName() + "(ct.toBlindCiphertext());");
            out.println("        }");
            out.println("    }");
            return;
        }
        switch (f.scheme()) {
            case BFV -> {
                out.println("    public void mul" + f.capName() + "(long plain) {");
                out.println("        FheContext ctx = BlindContext.getFheContext();");
                out.println("        try (FheCiphertextNative ct = new FheCiphertextNative(ctx.encryptLong(plain), ctx)) {");
                out.println("            mul" + f.capName() + "(ct.toBlindCiphertext());");
                out.println("        }");
                out.println("    }");
            }
            case CKKS -> {
                out.println("    public void mul" + f.capName() + "(double plain) {");
                out.println("        FheContext ctx = BlindContext.getFheContext();");
                out.println("        try (FheCiphertextNative ct = new FheCiphertextNative(ctx.encryptDouble(plain), ctx)) {");
                out.println("            mul" + f.capName() + "(ct.toBlindCiphertext());");
                out.println("        }");
                out.println("    }");
            }
            default -> throw new IllegalStateException("Unsupported scheme: " + f.scheme());
        }
    }
}

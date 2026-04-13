package com.blindbean.processor;

import com.blindbean.annotations.BlindEntity;
import com.blindbean.annotations.Homomorphic;
import com.google.auto.service.AutoService;

import javax.annotation.processing.AbstractProcessor;
import javax.annotation.processing.Processor;
import javax.annotation.processing.RoundEnvironment;
import javax.annotation.processing.SupportedAnnotationTypes;
import javax.annotation.processing.SupportedSourceVersion;
import javax.lang.model.SourceVersion;
import javax.lang.model.element.Element;
import javax.lang.model.element.ElementKind;
import javax.lang.model.element.TypeElement;
import javax.tools.Diagnostic;
import javax.tools.JavaFileObject;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Set;

@SupportedAnnotationTypes("com.blindbean.annotations.BlindEntity")
@SupportedSourceVersion(SourceVersion.RELEASE_26)
@AutoService(Processor.class)
public class HomomorphicProcessor extends AbstractProcessor {

    @Override
    public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment roundEnv) {
        for (Element element : roundEnv.getElementsAnnotatedWith(BlindEntity.class)) {
            if (element.getKind() != ElementKind.CLASS) {
                processingEnv.getMessager().printMessage(Diagnostic.Kind.ERROR, "@BlindEntity only applies to classes");
                return true;
            }

            TypeElement typeElement = (TypeElement) element;
            String className = typeElement.getSimpleName().toString();
            String packageName = processingEnv.getElementUtils().getPackageOf(typeElement).getQualifiedName().toString();

            generateBlindWrapper(packageName, className, typeElement);
        }
        return true;
    }

    private void generateBlindWrapper(String packageName, String className, TypeElement typeElement) {
        String wrapperName = className + "BlindWrapper";
        try {
            JavaFileObject builderFile = processingEnv.getFiler().createSourceFile(packageName + "." + wrapperName);
            try (PrintWriter out = new PrintWriter(builderFile.openWriter())) {
                out.println("package " + packageName + ";");
                out.println("");
                out.println("import com.blindbean.core.Ciphertext;");
                out.println("import com.blindbean.math.BlindMath;");
                out.println("");
                out.println("public class " + wrapperName + " {");
                out.println("    private final " + className + " entity;");
                out.println("");
                out.println("    public " + wrapperName + "(" + className + " entity) {");
                out.println("        this.entity = entity;");
                out.println("    }");
                out.println("");

                // A simplified dummy method showing how to add to the entity using Reflection or Direct Access.
                // In a production library this would rely on the field type or getters/setters.
                for (Element enclosed : typeElement.getEnclosedElements()) {
                    if (enclosed.getKind() == ElementKind.FIELD && enclosed.getAnnotation(Homomorphic.class) != null) {
                        String fieldName = enclosed.getSimpleName().toString();
                        String capName = fieldName.substring(0, 1).toUpperCase() + fieldName.substring(1);
                        
                        out.println("    public void add" + capName + "(Ciphertext amountToAdd) {");
                        out.println("        // Intercepts the field, decodes string to Ciphertext, adds, and sets back string.");
                        out.println("        // In this prototype, we rely on String getters/setters or direct field if accessible.");
                        out.println("        Ciphertext current = new Ciphertext(entity.get" + capName + "(), amountToAdd.scheme());");
                        out.println("        Ciphertext sum = BlindMath.add(current, amountToAdd);");
                        out.println("        entity.set" + capName + "(sum.hexData());");
                        out.println("    }");
                    }
                }

                out.println("}");
            }
        } catch (IOException e) {
            processingEnv.getMessager().printMessage(Diagnostic.Kind.ERROR, e.toString());
        }
    }
}

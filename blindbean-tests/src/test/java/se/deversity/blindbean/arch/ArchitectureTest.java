package se.deversity.blindbean.arch;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.ArchRule;
import java.net.URL;
import java.util.LinkedHashSet;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static com.tngtech.archunit.library.Architectures.layeredArchitecture;

/**
 * Turns the module-boundary guardrails documented in {@code CLAUDE.md} into failing tests.
 *
 * <p>These rules analyse the <em>compiled bytecode</em> of the six library modules, so
 * source-only artefacts (the {@code @AI*} SOURCE-retention annotations, and the import/runtime
 * statements the processor <em>emits as strings</em>) never register as dependencies — which is
 * exactly why the processor stays clean at the bytecode level even though its source mentions
 * {@code se.deversity.blindbean.math} in a generated template.
 *
 * <p>Boundaries are enforced at <em>module</em> granularity, not per package: {@code math} and
 * {@code context} form a deliberate, documented cycle inside the single {@code -runtime} module
 * ({@code BlindMath} dispatches into {@code context}; {@code context} uses the Paillier types
 * back), so a naive package-cycle check would wrongly flag it. Grouping both under one Runtime
 * layer allows that intra-layer edge while still forbidding any upward leak.
 */
@DisplayName("Architecture: module boundaries")
class ArchitectureTest {

    /** Production bytecode of every library module; test classes excluded. */
    private static JavaClasses libraryClasses;

    @BeforeAll
    static void importLibrary() {
        // Under Maven surefire the real dependency jars sit behind a manifest-only booter jar, so
        // ArchUnit's default java.class.path scan (importPackages / importPackagesOf) finds nothing
        // and every layer reads empty. Resolve each module jar directly from an anchor class's code
        // source instead — one public type per module (runtime's jar covers math+context+async).
        Class<?>[] anchors = {
                se.deversity.blindbean.annotations.BlindEntity.class,
                se.deversity.blindbean.core.Ciphertext.class,
                se.deversity.blindbean.fhe.FheContext.class,
                se.deversity.blindbean.math.BlindMath.class,
                se.deversity.blindbean.context.BlindContext.class,
                se.deversity.blindbean.async.BlindAsync.class,
                se.deversity.blindbean.processor.HomomorphicProcessor.class,
                se.deversity.blindbean.junit.BlindBeanExtension.class,
        };
        Set<URL> moduleLocations = new LinkedHashSet<>();
        for (Class<?> anchor : anchors) {
            moduleLocations.add(anchor.getProtectionDomain().getCodeSource().getLocation());
        }
        libraryClasses = new ClassFileImporter()
                .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
                .importUrls(new java.util.ArrayList<>(moduleLocations));
    }

    @Test
    @DisplayName("layering: no module depends upward; processor pulls annotations only")
    void respectsModuleLayering() {
        ArchRule rule = layeredArchitecture().consideringOnlyDependenciesInLayers()
                .layer("Annotations").definedBy("se.deversity.blindbean.annotations..")
                .layer("Core").definedBy("se.deversity.blindbean.core..")
                .layer("Fhe").definedBy("se.deversity.blindbean.fhe..")
                // math + context + async ship together as -runtime (documented math<->context cycle)
                .layer("Runtime").definedBy(
                        "se.deversity.blindbean.math..",
                        "se.deversity.blindbean.context..",
                        "se.deversity.blindbean.async..")
                .layer("Processor").definedBy("se.deversity.blindbean.processor..")
                .layer("Junit").definedBy("se.deversity.blindbean.junit..")

                .whereLayer("Annotations").mayNotAccessAnyLayer()
                .whereLayer("Core").mayOnlyAccessLayers("Annotations")
                .whereLayer("Fhe").mayOnlyAccessLayers("Core", "Annotations")
                .whereLayer("Runtime").mayOnlyAccessLayers("Fhe", "Core", "Annotations")
                // the crown-jewel guarantee: a consumer's compile path must not pull runtime/native/vector
                .whereLayer("Processor").mayOnlyAccessLayers("Annotations")
                .whereLayer("Junit").mayOnlyAccessLayers("Runtime", "Fhe", "Core", "Annotations");

        rule.check(libraryClasses);
    }

    @Test
    @DisplayName("math layer must not reach the native bridge (BlindMath dispatches via BlindContext)")
    void mathLayerDoesNotTouchTheNativeBridge() {
        ArchRule rule = noClasses()
                .that().resideInAPackage("se.deversity.blindbean.math..")
                .should().dependOnClassesThat()
                .haveFullyQualifiedName("se.deversity.blindbean.fhe.FheNativeBridge");

        rule.check(libraryClasses);
    }

    @Test
    @DisplayName("Ciphertext is a pure domain model — no web/persistence framework deps")
    void ciphertextStaysAPureDomainModel() {
        ArchRule rule = noClasses()
                .that().haveFullyQualifiedName("se.deversity.blindbean.core.Ciphertext")
                .should().dependOnClassesThat()
                .resideInAnyPackage(
                        "org.springframework..",
                        "jakarta.persistence..",
                        "javax.persistence..",
                        "org.hibernate..",
                        "com.fasterxml.jackson..");

        rule.check(libraryClasses);
    }

    @Test
    @DisplayName("KeyBundle key material is reachable only from within the context package")
    void keyBundleIsAccessedOnlyFromContext() {
        ArchRule rule = classes()
                .that().haveFullyQualifiedName("se.deversity.blindbean.context.KeyBundle")
                .should().onlyHaveDependentClassesThat()
                .resideInAPackage("se.deversity.blindbean.context..");

        rule.check(libraryClasses);
    }
}

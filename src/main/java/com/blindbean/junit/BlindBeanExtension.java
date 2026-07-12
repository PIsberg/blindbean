package com.blindbean.junit;

import com.blindbean.annotations.Scheme;
import com.blindbean.context.BlindContext;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import se.deversity.vibetags.annotations.AIContract;
import se.deversity.vibetags.annotations.AIIdempotent;
import se.deversity.vibetags.annotations.AIPublicAPI;
import se.deversity.vibetags.annotations.AITestDriven;

import java.util.Optional;

/**
 * JUnit 5 extension backing {@link BlindBeanTest}: initializes the
 * {@code BlindContext} (and, when requested, the native BFV/CKKS context)
 * before each test method and clears all cryptographic state afterwards,
 * so tests never leak keys or native handles into each other.
 *
 * <p>Can also be applied directly with
 * {@code @ExtendWith(BlindBeanExtension.class)}, which behaves like the
 * annotation's defaults (Paillier only).</p>
 */
@AIPublicAPI(reason = "Consumers reference this extension directly via @ExtendWith and inherit it through @BlindBeanTest; renaming or changing its callbacks breaks every downstream test suite")
@AITestDriven(coverageGoal = 90, testLocation = "src/test/java/com/blindbean/junit")
public final class BlindBeanExtension implements BeforeEachCallback, AfterEachCallback {

    @Override
    @AIContract(reason = "JUnit 5 BeforeEachCallback contract — signature is fixed by the framework SPI")
    public void beforeEach(ExtensionContext context) {
        BlindContext.init();
        Optional<BlindBeanTest> cfg = findConfig(context);
        if (cfg.isPresent()) {
            BlindBeanTest annotation = cfg.get();
            switch (annotation.scheme()) {
                case BFV -> BlindContext.initBfv(annotation.polyModulusDegree());
                case CKKS -> BlindContext.initCkks(annotation.polyModulusDegree(), annotation.ckksScale());
                case PAILLIER -> { /* Paillier is already initialized above */ }
            }
        }
    }

    @Override
    @AIIdempotent(reason = "Cleanup must tolerate a failed/partial beforeEach and repeated invocation — BlindContext.clear() is itself idempotent; never make teardown conditional on setup having succeeded, or a failing test would leak keys and native handles into the next one")
    public void afterEach(ExtensionContext context) {
        BlindContext.clear();
    }

    private static Optional<BlindBeanTest> findConfig(ExtensionContext context) {
        // Walk the class hierarchy of the test (covers @Nested classes whose
        // enclosing class carries the annotation).
        ExtensionContext current = context;
        while (current != null) {
            Optional<BlindBeanTest> found = current.getTestClass()
                .map(c -> c.getAnnotation(BlindBeanTest.class))
                .filter(a -> a != null);
            if (found.isPresent()) {
                return found;
            }
            current = current.getParent().orElse(null);
        }
        return Optional.empty();
    }
}

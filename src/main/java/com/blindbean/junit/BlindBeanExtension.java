package com.blindbean.junit;

import com.blindbean.annotations.Scheme;
import com.blindbean.context.BlindContext;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

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
public final class BlindBeanExtension implements BeforeEachCallback, AfterEachCallback {

    @Override
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

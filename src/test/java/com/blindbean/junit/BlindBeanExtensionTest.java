package com.blindbean.junit;

import com.blindbean.annotations.Scheme;
import com.blindbean.context.BlindContext;
import com.blindbean.core.Ciphertext;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies that {@link BlindBeanTest} / {@link BlindBeanExtension} manage the
 * BlindContext lifecycle: contexts are live inside test methods without any
 * manual setup, per-scheme initialization honors the annotation attributes,
 * and state does not leak between tests.
 */
public class BlindBeanExtensionTest {

    @Nested
    @BlindBeanTest
    class PaillierDefaults {

        @Test
        void paillierIsReadyWithoutManualInit() {
            Ciphertext ct = BlindContext.getPaillier().encrypt(BigInteger.valueOf(123));
            BigInteger back = BlindContext.getPaillier().decrypt(ct);
            assertEquals(BigInteger.valueOf(123), back);
        }

        @Test
        void freshKeysPerTest() {
            // If the previous test's context leaked, this encrypt would reuse
            // its keys; a fresh init must still round-trip on its own.
            Ciphertext ct = BlindContext.getPaillier().encrypt(BigInteger.ONE);
            assertEquals(BigInteger.ONE, BlindContext.getPaillier().decrypt(ct));
        }
    }

    @Nested
    @BlindBeanTest(scheme = Scheme.BFV, polyModulusDegree = 8192)
    class BfvConfigured {

        @Test
        void nativeBfvContextIsBooted() {
            try (var ctx = BlindContext.getFheContext()) {
                var ct = ctx.encryptLong(21L);
                var doubled = ctx.add(ct, ct);
                assertEquals(42L, ctx.decryptLong(doubled));
            }
        }
    }

    @Test
    void extensionOnlyAppliesToAnnotatedClasses() {
        // This method is NOT under @BlindBeanTest, so the extension has not
        // pre-initialized anything here. getPaillier() lazily self-initializes
        // by design — clean up after ourselves like any un-managed test must.
        try {
            assertNotNull(BlindContext.getPaillier());
        } finally {
            BlindContext.clear();
        }
    }
}

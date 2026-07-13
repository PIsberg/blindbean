package com.blindbean.context;

import com.blindbean.core.Ciphertext;
import com.blindbean.math.PaillierKeyPair;
import com.blindbean.math.PaillierMath;

import se.deversity.asynctest.AsyncTest;
import se.deversity.asynctest.BeforeEachInvocation;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;

import java.math.BigInteger;
import java.util.concurrent.ThreadLocalRandom;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Concurrency stress for {@link BlindRotation}.
 *
 * <p>A real rotation batch is fanned out across threads, so {@code rotate()} is a concurrent entry
 * point by design: it drives two {@link PaillierMath} instances — each holding a shared
 * {@link java.security.SecureRandom} — plus an atomic counter, all from many threads at once.
 * The crypto detectors are the point here: a stateful cipher or a badly shared RNG on this path
 * would silently weaken or corrupt every rotated ciphertext.
 *
 * <p>Key pairs are generated once per class, not per invocation — 1024-bit prime generation per
 * round would dominate the run and starve the very interleavings we want to observe.
 */
class RotationAsyncConcurrencyTest {

    private static final PaillierKeyPair SOURCE_KEYS = new PaillierKeyPair(1024);
    private static final PaillierKeyPair TARGET_KEYS = new PaillierKeyPair(1024);
    private static final PaillierMath SOURCE_MATH = new PaillierMath(SOURCE_KEYS);
    private static final PaillierMath TARGET_MATH = new PaillierMath(TARGET_KEYS);

    private BlindRotation rotation;

    @BeforeEach
    void setup() {
        BlindContext.clear();
    }

    @AfterEach
    void teardown() {
        if (rotation != null) {
            rotation.close();
        }
        BlindContext.clear();
    }

    /** A fresh session per round, so the rotated counter and the closed/committed flags start clean. */
    @BeforeEachInvocation
    void freshSession() {
        if (rotation != null) {
            rotation.close();
        }
        rotation = BlindRotation.paillier(SOURCE_KEYS, TARGET_KEYS);
    }

    /**
     * Every thread rotates its own ciphertext through the shared session. Each value must come out
     * the other side intact — a race in the shared SecureRandom or in the counter would show up as
     * a corrupted plaintext or a lost increment.
     */
    @AsyncTest(
        threads = 16,
        invocations = 20,
        detectRaceConditions = true,
        detectAtomicityViolations = true,
        detectSharedSecureRandom = true,
        detectSharedStatefulCrypto = true,
        detectVisibility = true,
        timeoutMs = 60000
    )
    void concurrentRotationPreservesEveryValue() {
        long raw = ThreadLocalRandom.current().nextLong(1_000_000L);
        BigInteger original = BigInteger.valueOf(raw);

        Ciphertext underOld = SOURCE_MATH.encrypt(original);
        Ciphertext underNew = rotation.rotate(underOld);

        assertEquals(original, TARGET_MATH.decrypt(underNew),
            "a concurrently rotated ciphertext must decrypt to its original value under the new keys");
    }
}

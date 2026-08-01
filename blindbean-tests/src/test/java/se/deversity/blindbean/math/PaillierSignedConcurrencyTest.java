package se.deversity.blindbean.math;

import se.deversity.blindbean.core.Ciphertext;

import se.deversity.asynctest.AsyncTest;
import se.deversity.asynctest.AsyncTestContext;
import se.deversity.asynctest.Preset;

import java.math.BigInteger;
import java.util.concurrent.ThreadLocalRandom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The balanced-representation decode, under real thread collisions.
 *
 * <p>{@code decryptSigned} is a project invariant: numeric fields decode through it, while strings
 * and {@code byte[]} keep plain {@code decrypt}. {@link PaillierSignedTest} pins the arithmetic
 * single-threaded. What was never pinned is that one {@link PaillierMath} instance, shared across
 * threads, decodes the same way on all of them.
 *
 * <p>That sharing is not incidental. {@code BlindContext} hands the same {@code PaillierMath} to
 * every thread that asks, so if the instance carried per-operation state the failure would not be
 * an exception, it would be a wrong number: the signed decode turns a residue above n/2 into a
 * negative, and a decode that read another thread's residue would hand back a plausible value of
 * the wrong sign. A balance of -7 that reads as a 600-digit positive, or the reverse, is exactly
 * the class of corruption this library exists to prevent, and it is silent.
 *
 * <p>Negative values carry the risk here, so the fixtures are weighted towards them: a decode that
 * loses the balanced representation still looks correct for every positive input.
 *
 * <p>No {@code @Tag("native")}: Paillier is pure Java, so this runs in the Linux fast gate.
 */
class PaillierSignedConcurrencyTest {

    /**
     * 512-bit, test-only, matching {@link PaillierSignedTest}. Chosen for keygen speed, not
     * security; see {@code BlindContext.DEFAULT_PAILLIER_BITS} for the production size. Built once
     * per class so the barrier opens on decode work rather than on prime generation.
     */
    private static final PaillierMath MATH = new PaillierMath(new PaillierKeyPair(512));

    /** Deliberately negative-heavy: a broken signed decode is invisible on positives. */
    private static final long[] VALUES = {-7L, -1L, -1_000_000L, 0L, 1L, 42L};

    // ── 1. The signed round trip ──────────────────────────────────────────

    /**
     * Every thread encrypts one of the fixtures through the shared instance and decodes it back.
     * The value must survive exactly, sign included.
     *
     * <p>The body also declares its read of the shared {@code MATH} to the race detector, through
     * the {@code AsyncTestContext} accessor added in async-test-lib 1.7.0-RC5. Worth being exact
     * about what that buys: a test cannot instrument {@code PaillierMath}'s own fields from
     * outside, so this records the one thing it can see honestly, that every thread reaches the
     * same instance. The assertion below is what actually catches a stateful decode; the
     * instrumentation makes the report name {@code MATH} instead of leaving a bare mismatch.
     */
    @AsyncTest(
        threads = 12,
        invocations = 20,
        detectAll = false,
        detectRaceConditions = true,
        detectAtomicityViolations = true,
        detectSharedSecureRandom = true,
        detectSharedStatefulCrypto = true,
        detectSharedMessageDigest = true,
        timeoutMs = 60000
    )
    void signedValuesRoundTripThroughASharedInstance() {
        AsyncTestContext.raceConditionDetector().recordFieldRead(MATH, "MATH");

        long raw = VALUES[ThreadLocalRandom.current().nextInt(VALUES.length)];
        BigInteger expected = BigInteger.valueOf(raw);

        assertEquals(expected, MATH.decryptSigned(MATH.encrypt(expected)),
            "a shared PaillierMath must decode the caller's own value, sign included");
    }

    /**
     * The trap {@code decryptSigned} exists to correct, asserted concurrently: the raw
     * {@code decrypt} of a negative is the positive residue {@code n - v}. Strings and blobs still
     * read through that path, so it must stay reachable and stay unsigned even under load. If a
     * well-meaning change ever routed everything through the signed decode, this goes red.
     */
    @AsyncTest(
        threads = 12,
        invocations = 20,
        detectAll = false,
        detectRaceConditions = true,
        timeoutMs = 60000
    )
    void theRawDecodeStaysUnsignedOnEveryThread() {
        BigInteger negative = BigInteger.valueOf(-5L);
        BigInteger n = MATH.getKeyPair().getN();

        BigInteger raw = MATH.decrypt(MATH.encrypt(negative));

        assertEquals(n.subtract(BigInteger.valueOf(5L)), raw);
        assertTrue(raw.signum() > 0, "the residue is positive; that is the trap decryptSigned corrects");
    }

    // ── 2. The homomorphism agrees with the decode, concurrently ──────────

    /**
     * Addition that crosses zero, run at 4, 12 and 24 threads. The balanced representation has to
     * agree with the additive homomorphism at every contention level, not just when the scheduler
     * happens to serialise the work: {@code 3 - 10} must read as -7, never as {@code n - 7}.
     */
    @AsyncTest(
        threadCounts = {4, 12, 24},
        invocations = 10,
        preset = Preset.CI_FAST,
        timeoutMs = 60000
    )
    void additionAcrossZeroStaysNegativeAtEveryThreadCount() {
        Ciphertext diff = MATH.subtract(
            MATH.encrypt(BigInteger.valueOf(3L)),
            MATH.encrypt(BigInteger.valueOf(10L)));

        assertEquals(BigInteger.valueOf(-7L), MATH.decryptSigned(diff),
            "3 - 10 must be -7, not n-7, on every thread");
    }

    // ── 3. Probabilistic encryption survives the collision ────────────────

    /**
     * Paillier is probabilistic: encrypting the same value twice must give different ciphertexts,
     * because the randomiser differs. Concurrency is where that can quietly stop being true. If
     * the shared {@code SecureRandom} were replaced by something with per-instance state used
     * unsafely, or seeded per call, two threads could draw the same randomiser and produce
     * identical ciphertexts for identical input, which leaks equality of plaintexts to anyone
     * holding the ciphertexts.
     *
     * <p>Each thread encrypts the same constant twice and asserts the two differ, then asserts
     * both still decode. Collision would have to be observed within a single thread's pair, which
     * is the conservative form of the check: it cannot false-positive on unrelated threads
     * happening to agree.
     */
    @AsyncTest(
        threads = 16,
        invocations = 20,
        detectAll = false,
        detectSharedSecureRandom = true,
        detectSharedStatefulCrypto = true,
        detectRaceConditions = true,
        timeoutMs = 60000
    )
    void encryptionStaysProbabilisticUnderContention() {
        BigInteger value = BigInteger.valueOf(4242L);

        Ciphertext first = MATH.encrypt(value);
        Ciphertext second = MATH.encrypt(value);

        assertFalse(first.hexData().equals(second.hexData()),
            "two encryptions of one value must differ, or the ciphertext leaks plaintext equality");
        assertEquals(value, MATH.decryptSigned(first));
        assertEquals(value, MATH.decryptSigned(second));
    }
}

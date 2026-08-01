package se.deversity.blindbean.core;

import se.deversity.asynctest.AsyncTest;
import se.deversity.asynctest.Preset;

import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The key stamp under real thread collisions.
 *
 * <p>{@link KeyTagTest} pins what the stamp means; this pins that it still means it when many
 * threads hit it at once. The two are not the same guarantee. Every method on {@link KeyTag} is
 * static and the class holds no mutable state, so today the answer is yes by construction. That
 * construction is the thing worth defending: {@code sha256()} returns a <em>fresh</em>
 * {@link java.security.MessageDigest} per call, and a digest is stateful across
 * {@code update -> digest}. Caching one in a static field is an obvious-looking optimisation, it
 * removes a per-call allocation, and it would be catastrophic here: two threads interleaving
 * {@code update} and {@code digest} produce a tag derived from a blend of both inputs. The tag is
 * what stands between a rotation re-run and silently decrypting under the wrong key, so a wrong
 * tag is a false ACCEPT, not a failed test somewhere downstream.
 *
 * <p>These tests are behavioural rather than instrumented on purpose. Every case compares against
 * a reference computed single-threaded before any thread starts, so a shared-digest regression
 * fails on the assertion whether or not the detector that names it is enabled. The
 * {@code detectSharedMessageDigest} and {@code detectSharedStatefulCrypto} flags then say
 * <em>which</em> object was shared instead of leaving a bare byte-array mismatch.
 *
 * <p>No {@code @Tag("native")}: this touches no SEAL and needs no DLL, so it runs in the Linux
 * fast gate.
 */
class KeyTagConcurrencyTest {

    /** Distinct key material, standing in for distinct key generations. */
    private static final byte[][] MATERIAL = {
        "generation-alpha".getBytes(),
        "generation-beta".getBytes(),
        "generation-gamma".getBytes(),
        "generation-delta".getBytes(),
    };

    /** Derived once, single-threaded, before any collision. The answer every thread must reproduce. */
    private static final byte[][] REFERENCE_TAGS = {
        KeyTag.derive(MATERIAL[0]),
        KeyTag.derive(MATERIAL[1]),
        KeyTag.derive(MATERIAL[2]),
        KeyTag.derive(MATERIAL[3]),
    };

    private static final byte[] PAYLOAD = "the ciphertext bytes that must come back whole".getBytes();

    /** Stamped under generation alpha. */
    private static final byte[] ENVELOPE_ALPHA = KeyTag.wrap(REFERENCE_TAGS[0], PAYLOAD);

    /** The same payload stamped under a different generation: the thing that must be refused. */
    private static final byte[] ENVELOPE_BETA = KeyTag.wrap(REFERENCE_TAGS[1], PAYLOAD);

    // ── 1. derive() is a pure function of its input, on every thread ───────

    /**
     * Twenty threads derive tags from four inputs at once. Each must get exactly the tag computed
     * for that input before the barrier opened.
     *
     * <p>This is the test that goes red if {@code sha256()} ever starts handing out a shared
     * digest: the interleaved {@code update} calls fold two generations' material into one tag,
     * and the comparison against {@code REFERENCE_TAGS} fails on the first collision.
     */
    @AsyncTest(
        threads = 20,
        invocations = 50,
        detectAll = false,
        detectSharedMessageDigest = true,
        detectSharedStatefulCrypto = true,
        detectRaceConditions = true,
        timeoutMs = 15000
    )
    void deriveReturnsTheSameTagOnEveryThread() {
        int i = ThreadLocalRandom.current().nextInt(MATERIAL.length);

        assertArrayEquals(REFERENCE_TAGS[i], KeyTag.derive(MATERIAL[i]),
            "derive() must be a pure function of its input; a tag that depends on which threads "
            + "were running is a tag that cannot identify a key generation");
    }

    /**
     * The same input on every thread, which is the arrangement most likely to hide a shared
     * digest: if all threads feed identical bytes, a blended state can still produce the
     * <em>expected</em> answer by luck. Distinct inputs are checked above; this one additionally
     * pins that concurrent derivation of one generation never drifts.
     */
    @AsyncTest(
        threads = 32,
        invocations = 30,
        detectAll = false,
        detectSharedMessageDigest = true,
        detectRaceConditions = true,
        timeoutMs = 15000
    )
    void deriveOfOneGenerationIsStableAcrossThreads() {
        assertArrayEquals(REFERENCE_TAGS[0], KeyTag.derive(MATERIAL[0]));
        assertEquals(KeyTag.TAG_LENGTH, KeyTag.derive(MATERIAL[0]).length,
            "a short tag would still pass the header check and shift the payload");
    }

    // ── 2. The false-ACCEPT boundary ──────────────────────────────────────

    /**
     * The security assertion of this file. Each thread randomly either verifies a matching
     * envelope, which must return the payload whole, or a foreign one, which must be refused with
     * {@link WrongKeyException}. Both outcomes are asserted exactly, so neither a false ACCEPT nor
     * a false REJECT can pass as success.
     *
     * <p>A false ACCEPT here is the failure that motivated the stamp: Paillier decryption under a
     * foreign key does not fail, it returns a plausible wrong number. If concurrency could make
     * {@code verifyAndUnwrap} miss a mismatch even occasionally, the stamp would stop being a
     * boundary and become a suggestion.
     */
    @AsyncTest(
        threads = 24,
        invocations = 50,
        preset = Preset.ESSENTIALS,
        timeoutMs = 15000
    )
    void verifyAndUnwrapNeverAcceptsAForeignGenerationsTag() {
        boolean useMatching = ThreadLocalRandom.current().nextBoolean();

        if (useMatching) {
            byte[] out = KeyTag.verifyAndUnwrap(ENVELOPE_ALPHA, REFERENCE_TAGS[0], "decrypt");
            assertArrayEquals(PAYLOAD, out,
                "a matching tag must return the payload whole, with the header stripped");
        } else {
            WrongKeyException e = assertThrows(WrongKeyException.class,
                () -> KeyTag.verifyAndUnwrap(ENVELOPE_BETA, REFERENCE_TAGS[0], "decrypt"),
                "a foreign generation's tag must be refused, never unwrapped");
            assertFalse(Arrays.equals(e.expectedTag(), e.actualTag()),
                "the refusal must carry the two tags that actually differed");
        }
    }

    // ── 3. The same guarantee across a contention sweep ────────────────────

    /**
     * A wrap/unwrap round trip at 2, 8 and 32 threads. {@code threadCounts} runs one JUnit
     * invocation per entry, which is the cheap way to ask whether a guarantee that holds at low
     * contention still holds once the scheduler has room to interleave. A defect that needs 32
     * threads to surface is invisible at 2.
     */
    @AsyncTest(
        threadCounts = {2, 8, 32},
        invocations = 25,
        preset = Preset.CI_FAST,
        timeoutMs = 15000
    )
    void wrapAndUnwrapRoundTripHoldsAtEveryThreadCount() {
        int i = ThreadLocalRandom.current().nextInt(MATERIAL.length);
        byte[] enveloped = KeyTag.wrap(REFERENCE_TAGS[i], PAYLOAD);

        assertTrue(KeyTag.isTagged(enveloped));
        assertArrayEquals(REFERENCE_TAGS[i], KeyTag.tagOf(enveloped));
        assertArrayEquals(PAYLOAD, KeyTag.payloadOf(enveloped));
    }

    // ── 4. Legacy payloads stay readable ──────────────────────────────────

    /**
     * Untagged data written before the stamp existed must keep reading as legacy under
     * contention, not start being mistaken for a corrupt header. Losing this would make every
     * pre-stamp ciphertext undecryptable, which is a data-loss bug rather than a security one,
     * and it would show up only under load if the header check were ever made stateful.
     */
    @AsyncTest(
        threads = 16,
        invocations = 50,
        detectAll = false,
        detectRaceConditions = true,
        detectVisibility = true,
        timeoutMs = 10000
    )
    void legacyUntaggedPayloadsStayReadableUnderContention() {
        assertFalse(KeyTag.isTagged(PAYLOAD), "fixture must actually be untagged");
        assertNull(KeyTag.tagOf(PAYLOAD));
        assertArrayEquals(PAYLOAD, KeyTag.payloadOf(PAYLOAD),
            "a legacy payload is returned whole, never truncated by a header that is not there");
    }
}

package com.blindbean.core;

import com.blindbean.annotations.Scheme;
import com.blindbean.context.BlindRotation;
import com.blindbean.math.PaillierKeyPair;
import com.blindbean.math.PaillierMath;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The key-generation stamp, and the corruption it exists to stop.
 *
 * <p>The headline test is {@link #decryptingUnderTheWrongKeyIsRefusedNotGuessedAt()}: before the
 * stamp, that call returned a plausible wrong number instead of failing, which is what made a
 * re-run key rotation destroy data without anyone noticing. Key material is never asserted on —
 * only the public modulus and plaintext this test chose itself.
 */
public class KeyTagTest {

    // 512-bit keys: test-only, chosen for keygen speed. Not a production size.
    private static PaillierKeyPair keys() {
        return new PaillierKeyPair(512);
    }

    @Test
    public void decryptingUnderTheWrongKeyIsRefusedNotGuessedAt() {
        PaillierMath alice = new PaillierMath(keys());
        PaillierMath bob = new PaillierMath(keys());

        Ciphertext underAlice = alice.encrypt(BigInteger.valueOf(4242L));

        // The bug: Paillier decryption under a foreign key does not fail — c^lambda = 1 (mod n)
        // for any c coprime to n, so L() divides exactly and a wrong-but-well-formed plaintext
        // comes back. It must be refused on the tag instead.
        WrongKeyException e = assertThrows(WrongKeyException.class, () -> bob.decrypt(underAlice));
        assertFalse(Arrays.equals(e.expectedTag(), e.actualTag()));
        assertTrue(e.getMessage().contains("ALREADY"),
            "the message must tell a rotation re-run what actually happened");
    }

    @Test
    public void aRotatedValueCannotBeRotatedTwice() {
        // The exact scenario that used to corrupt: a batch dies halfway, is re-run, and feeds
        // an already-rotated row back through the old key.
        PaillierKeyPair oldKeys = keys();
        PaillierKeyPair newKeys = keys();
        BigInteger balance = BigInteger.valueOf(100_000L);

        Ciphertext underOld = new PaillierMath(oldKeys).encrypt(balance);

        Ciphertext underNew;
        try (BlindRotation rotation = BlindRotation.paillier(oldKeys, newKeys)) {
            underNew = rotation.rotate(underOld);
        }
        assertEquals(balance, new PaillierMath(newKeys).decrypt(underNew));

        // Re-run of the same batch over a row that already moved.
        try (BlindRotation rerun = BlindRotation.paillier(oldKeys, newKeys)) {
            assertThrows(WrongKeyException.class, () -> rerun.rotate(underNew),
                "re-rotating an already-rotated value must be refused, not silently corrupt it");
        }

        // And the value is still intact — the point of refusing rather than mangling.
        assertEquals(balance, new PaillierMath(newKeys).decrypt(underNew));
    }

    @Test
    public void homomorphicOpsRejectAForeignCiphertext() {
        PaillierMath alice = new PaillierMath(keys());
        PaillierMath bob = new PaillierMath(keys());

        Ciphertext a = alice.encrypt(BigInteger.ONE);
        Ciphertext foreign = bob.encrypt(BigInteger.ONE);

        assertThrows(WrongKeyException.class, () -> alice.add(a, foreign));
        assertThrows(WrongKeyException.class, () -> alice.subtract(a, foreign));
    }

    @Test
    public void additionStillWorksAndStaysTagged() {
        PaillierMath m = new PaillierMath(keys());
        Ciphertext sum = m.add(m.encrypt(BigInteger.valueOf(20)), m.encrypt(BigInteger.valueOf(22)));

        assertEquals(BigInteger.valueOf(42), m.decrypt(sum));
        assertArrayEquals(m.keyTag(), KeyTag.tagOf(sum.getBytes()),
            "the result of a homomorphic op must carry the tag too, or it is unrotatable");
    }

    @Test
    public void legacyUntaggedCiphertextsStillDecrypt() {
        // Data written before the stamp existed must not become unreadable. A payload with no
        // header is read as legacy and accepted; it is only unprotected until it is rewritten.
        PaillierKeyPair kp = keys();
        PaillierMath m = new PaillierMath(kp);

        Ciphertext tagged = m.encrypt(BigInteger.valueOf(7));
        byte[] legacyBytes = KeyTag.payloadOf(tagged.getBytes());
        Ciphertext legacy = Ciphertext.fromBytes(legacyBytes, Scheme.PAILLIER);

        assertNull(KeyTag.tagOf(legacy.getBytes()), "fixture must actually be untagged");
        assertEquals(BigInteger.valueOf(7), m.decrypt(legacy));
    }

    @Test
    public void theTagIsStableForAKeyAndDistinctBetweenKeys() {
        PaillierKeyPair kp = keys();
        assertArrayEquals(new PaillierMath(kp).keyTag(), new PaillierMath(kp).keyTag(),
            "the tag must be derived from the key, not assigned per instance — a restart must "
            + "not repudiate the ciphertexts it wrote before");
        assertFalse(Arrays.equals(new PaillierMath(keys()).keyTag(), new PaillierMath(keys()).keyTag()));
    }

    @Test
    public void wrapRoundTrips() {
        byte[] tag = KeyTag.derive("some-key".getBytes());
        byte[] payload = {1, 2, 3, 4, 5};
        byte[] enveloped = KeyTag.wrap(tag, payload);

        assertTrue(KeyTag.isTagged(enveloped));
        assertArrayEquals(tag, KeyTag.tagOf(enveloped));
        assertArrayEquals(payload, KeyTag.payloadOf(enveloped));
        assertEquals(KeyTag.TAG_LENGTH, tag.length);
    }
}

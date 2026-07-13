package com.blindbean.context;

import com.blindbean.annotations.Scheme;
import com.blindbean.core.Ciphertext;
import com.blindbean.math.PaillierKeyPair;
import com.blindbean.math.PaillierMath;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Key-rotation session tests. Assertions never touch private key material — only the public
 * modulus, and plaintext the test itself chose.
 */
public class BlindRotationTest {

    @AfterEach
    public void teardown() {
        BlindContext.clear();
    }

    @Test
    public void rotatedCiphertextDecryptsUnderTheNewKeysOnly() {
        PaillierKeyPair oldKeys = new PaillierKeyPair(512);
        PaillierKeyPair newKeys = new PaillierKeyPair(512);
        BigInteger message = BigInteger.valueOf(4242L);

        Ciphertext underOld = new PaillierMath(oldKeys).encrypt(message);

        Ciphertext underNew;
        try (BlindRotation rotation = BlindRotation.paillier(oldKeys, newKeys)) {
            underNew = rotation.rotate(underOld);
            assertEquals(1, rotation.rotatedCount());
        }

        assertEquals(message, new PaillierMath(newKeys).decrypt(underNew),
            "the rotated ciphertext must decrypt to the original plaintext under the new keys");
        assertNotEquals(underOld.hexData(), underNew.hexData(),
            "rotation must actually re-encrypt, not pass the ciphertext through");

        // The old keys must no longer recover the message from the rotated ciphertext.
        assertNotEquals(message, new PaillierMath(oldKeys).decrypt(underNew),
            "the retired keys must not decrypt a rotated ciphertext");
    }

    @Test
    public void fromCurrentRotatesOffTheInstalledContext() {
        BlindContext.init();
        BigInteger message = BigInteger.valueOf(31337L);
        Ciphertext underOld = BlindContext.getPaillier().encrypt(message);

        PaillierKeyPair newKeys = new PaillierKeyPair(512);
        try (BlindRotation rotation = BlindRotation.fromCurrent(newKeys)) {
            Ciphertext underNew = rotation.rotate(underOld);

            // Before commit the thread still runs on the old keys.
            assertFalse(rotation.isCommitted());
            assertEquals(message, BlindContext.getPaillier().decrypt(underOld),
                "an uncommitted rotation must not disturb the installed context");

            rotation.commit();
            assertTrue(rotation.isCommitted());
            assertEquals(message, BlindContext.getPaillier().decrypt(underNew),
                "after commit the thread must decrypt under the new keys");
        }
    }

    @Test
    public void commitIsIdempotent() {
        BlindContext.init();
        try (BlindRotation rotation = BlindRotation.fromCurrent(new PaillierKeyPair(512))) {
            rotation.commit();
            rotation.commit();
            assertTrue(rotation.isCommitted());
        }
    }

    @Test
    public void abandonedRotationLeavesTheContextUsable() {
        BlindContext.init();
        BigInteger message = BigInteger.valueOf(7L);
        Ciphertext underOld = BlindContext.getPaillier().encrypt(message);

        try (BlindRotation rotation = BlindRotation.fromCurrent(new PaillierKeyPair(512))) {
            rotation.rotate(underOld);
            // walk away without committing
        }

        assertEquals(message, BlindContext.getPaillier().decrypt(underOld),
            "abandoning a rotation must not strand the caller without a working key set");
    }

    @Test
    public void closedSessionRefusesFurtherRotation() {
        PaillierKeyPair oldKeys = new PaillierKeyPair(512);
        Ciphertext ct = new PaillierMath(oldKeys).encrypt(BigInteger.ONE);

        BlindRotation rotation = BlindRotation.paillier(oldKeys, new PaillierKeyPair(512));
        rotation.close();
        rotation.close(); // idempotent

        assertThrows(IllegalStateException.class, () -> rotation.rotate(ct));
        assertThrows(IllegalStateException.class, rotation::commit);
    }

    @Test
    public void rotatingOntoTheSameKeyIsRejected() {
        PaillierKeyPair keys = new PaillierKeyPair(512);
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> BlindRotation.paillier(keys, keys));
        assertTrue(e.getMessage().contains("same key"),
            "rotating onto the same modulus re-encrypts nothing and must be refused");
    }

    @Test
    public void aSessionRefusesCiphertextsFromAnotherScheme() {
        try (BlindRotation rotation =
                 BlindRotation.paillier(new PaillierKeyPair(512), new PaillierKeyPair(512))) {
            assertEquals(Scheme.PAILLIER, rotation.scheme());
            Ciphertext bfv = new Ciphertext("abcd", Scheme.BFV);
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> rotation.rotate(bfv));
            assertTrue(e.getMessage().contains("rotates PAILLIER"));
        }
    }

    @Test
    public void rotatingAfterCommitIsRefused() {
        BlindContext.init();
        Ciphertext ct = BlindContext.getPaillier().encrypt(BigInteger.TEN);

        try (BlindRotation rotation = BlindRotation.fromCurrent(new PaillierKeyPair(512))) {
            rotation.commit();
            IllegalStateException e = assertThrows(IllegalStateException.class, () -> rotation.rotate(ct));
            assertTrue(e.getMessage().contains("has been committed"),
                "rotating under retired keys after the app moved on is a bug, not a no-op");
        }
    }

    @Test
    public void rotateIsSafeUnderConcurrentUse() throws Exception {
        PaillierKeyPair oldKeys = new PaillierKeyPair(512);
        PaillierKeyPair newKeys = new PaillierKeyPair(512);
        PaillierMath oldMath = new PaillierMath(oldKeys);
        PaillierMath newMath = new PaillierMath(newKeys);

        int count = 64;
        List<Ciphertext> underOld = IntStream.range(0, count)
            .mapToObj(i -> oldMath.encrypt(BigInteger.valueOf(i)))
            .toList();

        try (BlindRotation rotation = BlindRotation.paillier(oldKeys, newKeys);
             ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {

            List<Callable<Ciphertext>> jobs = underOld.stream()
                .map(ct -> (Callable<Ciphertext>) () -> rotation.rotate(ct))
                .toList();

            List<Future<Ciphertext>> results = pool.invokeAll(jobs);
            for (int i = 0; i < count; i++) {
                assertEquals(BigInteger.valueOf(i), newMath.decrypt(results.get(i).get()),
                    "every concurrently rotated ciphertext must survive intact");
            }
            assertEquals(count, rotation.rotatedCount(), "the counter must not lose increments");
        }
    }
}

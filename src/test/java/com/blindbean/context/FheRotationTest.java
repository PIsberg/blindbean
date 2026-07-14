package com.blindbean.context;

import com.blindbean.annotations.Scheme;
import com.blindbean.core.Ciphertext;
import com.blindbean.fhe.FheCiphertextNative;
import com.blindbean.fhe.FheContext;
import com.blindbean.fhe.FheException;
import com.blindbean.core.WrongKeyException;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * BFV/CKKS key rotation. Needs the native SEAL bridge.
 */
@Tag("native")
public class FheRotationTest {

    private static final double CKKS_TOLERANCE = 0.01;

    @AfterEach
    public void teardown() {
        BlindContext.clear();
    }

    /** Encrypts under ctx and returns the portable ciphertext. */
    private static Ciphertext encryptLong(FheContext ctx, long value) {
        try (var ct = new FheCiphertextNative(ctx.encryptLong(value), ctx)) {
            return ct.toBlindCiphertext();
        }
    }

    private static long decryptLong(FheContext ctx, Ciphertext ct) {
        try (var handle = FheCiphertextNative.fromBlindCiphertext(ctx, ct)) {
            return ctx.decryptLong(handle.handle());
        }
    }

    @Test
    public void bfvCiphertextRotatesOntoFreshKeys() {
        BlindContext.initBfv(4096);
        FheContext oldCtx = BlindContext.getFheContext();
        Ciphertext underOld = encryptLong(oldCtx, 4242L);

        Ciphertext underNew;
        try (BlindRotation rotation = BlindRotation.fromCurrentFhe()) {
            assertEquals(Scheme.BFV, rotation.scheme());
            underNew = rotation.rotate(underOld);
            assertEquals(1, rotation.rotatedCount());

            rotation.commit();

            // The thread now runs on the new context, which must recover the value.
            assertEquals(4242L, decryptLong(BlindContext.getFheContext(), underNew),
                "the rotated ciphertext must decrypt under the new keys");
        }
        assertNotEquals(underOld.hexData(), underNew.hexData(),
            "rotation must actually re-encrypt, not pass the ciphertext through");
    }

    /**
     * A BFV ciphertext carries every batch slot regardless of how it was produced, so rotation
     * goes through the batch path in both directions and must preserve the whole vector.
     */
    @Test
    public void bfvBatchSurvivesRotationIntact() {
        BlindContext.initBfv(4096);
        FheContext oldCtx = BlindContext.getFheContext();

        long[] values = new long[4096];
        for (int i = 0; i < values.length; i++) {
            values[i] = i * 3L;
        }

        Ciphertext underOld;
        try (var ct = new FheCiphertextNative(oldCtx.encryptLongArray(values), oldCtx)) {
            underOld = ct.toBlindCiphertext();
        }

        try (BlindRotation rotation = BlindRotation.fromCurrentFhe()) {
            Ciphertext underNew = rotation.rotate(underOld);
            rotation.commit();

            FheContext newCtx = BlindContext.getFheContext();
            try (var handle = FheCiphertextNative.fromBlindCiphertext(newCtx, underNew)) {
                org.junit.jupiter.api.Assertions.assertArrayEquals(
                    values, newCtx.decryptLongArray(handle.handle()),
                    "every slot must survive the rotation");
            }
        }
    }

    /** A rotated BFV ciphertext must still be a usable operand, not just decryptable. */
    @Test
    public void rotatedBfvCiphertextStillAddsHomomorphically() {
        BlindContext.initBfv(4096);
        Ciphertext underOld = encryptLong(BlindContext.getFheContext(), 100L);

        try (BlindRotation rotation = BlindRotation.fromCurrentFhe()) {
            Ciphertext rotated = rotation.rotate(underOld);
            rotation.commit();

            FheContext ctx = BlindContext.getFheContext();
            Ciphertext addend = encryptLong(ctx, 23L);
            Ciphertext sum = com.blindbean.math.BlindMath.add(rotated, addend);

            assertEquals(123L, decryptLong(ctx, sum),
                "a rotated ciphertext must remain a first-class operand under the new keys");
        }
    }

    @Test
    public void ckksCiphertextRotatesOntoFreshKeys() {
        BlindContext.initCkks(8192, Math.pow(2, 40));
        FheContext oldCtx = BlindContext.getFheContext();

        Ciphertext underOld;
        try (var ct = new FheCiphertextNative(oldCtx.encryptDouble(3.14159), oldCtx)) {
            underOld = ct.toBlindCiphertext();
        }

        try (BlindRotation rotation = BlindRotation.fromCurrentFhe()) {
            assertEquals(Scheme.CKKS, rotation.scheme());
            Ciphertext underNew = rotation.rotate(underOld);
            rotation.commit();

            FheContext newCtx = BlindContext.getFheContext();
            try (var handle = FheCiphertextNative.fromBlindCiphertext(newCtx, underNew)) {
                assertEquals(3.14159, newCtx.decryptDouble(handle.handle()), CKKS_TOLERANCE,
                    "the rotated CKKS value must survive within approximation tolerance");
            }
        }
    }

    /** The retired context is closed on commit, so a committed rotation cannot leak it. */
    @Test
    public void commitRetiresTheOldContext() {
        BlindContext.initBfv(4096);
        FheContext oldCtx = BlindContext.getFheContext();

        try (BlindRotation rotation = BlindRotation.fromCurrentFhe()) {
            rotation.commit();
            assertNotEquals(oldCtx, BlindContext.getFheContext(), "the new context must be installed");
            assertThrows(FheException.class, () -> oldCtx.encryptLong(1L),
                "the retired context must be closed, not leaked");
        }
    }

    /** An abandoned FHE rotation must free the context it created and leave the thread usable. */
    @Test
    public void abandonedFheRotationFreesItsContextAndLeavesTheOldOneWorking() {
        BlindContext.initBfv(4096);
        FheContext oldCtx = BlindContext.getFheContext();
        Ciphertext underOld = encryptLong(oldCtx, 9L);

        try (BlindRotation rotation = BlindRotation.fromCurrentFhe()) {
            rotation.rotate(underOld);
            // walk away without committing
        }

        assertEquals(oldCtx, BlindContext.getFheContext(), "the original context must still be installed");
        assertEquals(9L, decryptLong(BlindContext.getFheContext(), underOld),
            "abandoning a rotation must leave the thread on working keys");
    }

    @Test
    public void mismatchedParametersAreRejected() {
        try (FheContext a = FheContext.bfv(4096);
             FheContext b = FheContext.bfv(8192);
             FheContext ckks = FheContext.ckks(8192, Math.pow(2, 40))) {

            IllegalArgumentException degree = assertThrows(IllegalArgumentException.class,
                () -> BlindRotation.fhe(a, b));
            assertTrue(degree.getMessage().contains("polyModulusDegree"),
                "a ciphertext cannot move between parameter sets");

            IllegalArgumentException scheme = assertThrows(IllegalArgumentException.class,
                () -> BlindRotation.fhe(b, ckks));
            assertTrue(scheme.getMessage().contains("same scheme"));

            assertThrows(IllegalArgumentException.class, () -> BlindRotation.fhe(a, a),
                "rotating a context onto itself re-encrypts nothing");
        }
    }

    /** An explicitly supplied target belongs to the caller and must not be closed by the session. */
    @Test
    public void explicitContextsAreNotClosedBySession() {
        try (FheContext source = FheContext.bfv(4096);
             FheContext target = FheContext.bfv(4096)) {

            Ciphertext underOld = encryptLong(source, 55L);
            Ciphertext underNew;
            try (BlindRotation rotation = BlindRotation.fhe(source, target)) {
                underNew = rotation.rotate(underOld);
            }

            // Both contexts must still be alive after the session closed.
            assertEquals(55L, decryptLong(target, underNew));
            assertEquals(55L, decryptLong(source, underOld));
        }
    }

    @Test
    public void fromCurrentFheRejectsAPaillierContext() {
        BlindContext.init();
        assertThrows(FheException.class, BlindRotation::fromCurrentFhe,
            "no FHE context is installed, so there is nothing to rotate");
    }

    /**
     * The FHE half of the re-rotation trap. SEAL does not save you here: the target context is
     * built with the same parameters, so it shares a {@code parms_id} with the source and an
     * already-rotated ciphertext deserializes cleanly into the old context and decrypts to noise
     * instead of failing. Only the key stamp catches it.
     */
    @Test
    public void anAlreadyRotatedBfvCiphertextCannotBeRotatedAgain() {
        BlindContext.initBfv(4096);
        Ciphertext underOld = encryptLong(BlindContext.getFheContext(), 4242L);

        FheContext source = BlindContext.getFheContext();
        try (FheContext target = FheContext.bfv(4096);
             BlindRotation rotation = BlindRotation.fhe(source, target)) {

            Ciphertext underNew = rotation.rotate(underOld);
            assertEquals(4242L, decryptLong(target, underNew));

            // The re-run: this row already moved.
            assertThrows(WrongKeyException.class, () -> rotation.rotate(underNew),
                "re-rotating an already-rotated BFV ciphertext must be refused, not decrypted to noise");

            // ...and it is intact, which is the whole point of refusing.
            assertEquals(4242L, decryptLong(target, underNew));
        }
    }

    /** A context that reloads its keys must still recognise the ciphertexts it wrote before. */
    @Test
    public void theKeyStampSurvivesAnExportImportRoundTrip() {
        BlindContext.initBfv(4096);
        FheContext ctx = BlindContext.getFheContext();
        Ciphertext ct = encryptLong(ctx, 77L);
        byte[] keys = ctx.exportState();

        try (FheContext reloaded = FheContext.bfv(4096)) {
            reloaded.importState(keys);
            assertEquals(77L, decryptLong(reloaded, ct),
                "a restarted context that reloads its key file must accept its own ciphertexts — "
                + "a randomly assigned key id would repudiate them here");
        }
    }
}

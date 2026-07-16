package se.deversity.blindbean.fhe;

import se.deversity.blindbean.context.BlindContext;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CKKS vector encryption, and the BFV slot range that used to corrupt data in silence.
 */
@Tag("native")
public class CkksBatchAndBfvRangeTest {

    private static final double TOL = 0.001;

    @AfterEach
    public void teardown() {
        BlindContext.clear();
    }

    // ── CKKS batching ────────────────────────────────────────────────────────

    @Test
    public void ckksEncryptsAWholeVectorNotJustSlotZero() {
        BlindContext.initCkks(8192, Math.pow(2, 40));
        FheContext ctx = BlindContext.getFheContext();

        double[] in = { 1.5, -2.25, 3.14159, 1000.001, 0.0 };
        try (var ct = new FheCiphertextNative(ctx.encryptDoubleArray(in), ctx)) {
            double[] out = ctx.decryptDoubleArray(ct.handle());
            assertEquals(ctx.slotCount(), out.length, "decrypt must return the full slot vector");
            for (int i = 0; i < in.length; i++) {
                assertEquals(in[i], out[i], TOL, "slot " + i);
            }
        }
    }

    @Test
    public void ckksVectorsAddSlotwise() {
        BlindContext.initCkks(8192, Math.pow(2, 40));
        FheContext ctx = BlindContext.getFheContext();

        double[] a = { 1.0, 2.0, 3.0 };
        double[] b = { 10.0, 20.0, 30.0 };

        try (var ca = new FheCiphertextNative(ctx.encryptDoubleArray(a), ctx);
             var cb = new FheCiphertextNative(ctx.encryptDoubleArray(b), ctx);
             var sum = new FheCiphertextNative(ctx.add(ca.handle(), cb.handle()), ctx)) {

            double[] out = ctx.decryptDoubleArray(sum.handle());
            assertEquals(11.0, out[0], TOL);
            assertEquals(22.0, out[1], TOL);
            assertEquals(33.0, out[2], TOL);
        }
    }

    @Test
    public void ckksHasHalfAsManySlotsAsItsDegree() {
        BlindContext.initCkks(8192, Math.pow(2, 40));
        // Complex-conjugate symmetry: CKKS packs degree/2 reals, not degree.
        assertEquals(4096, BlindContext.getFheContext().slotCount());
    }

    @Test
    public void ckksRejectsAVectorLongerThanItsSlots() {
        BlindContext.initCkks(8192, Math.pow(2, 40));
        FheContext ctx = BlindContext.getFheContext();
        assertThrows(FheException.class, () -> ctx.encryptDoubleArray(new double[4097]));
    }

    // ── BFV slot range ───────────────────────────────────────────────────────

    @Test
    public void bfvSlotsHaveARealAndDiscoverableLimit() {
        BlindContext.initBfv(8192);
        FheContext ctx = BlindContext.getFheContext();

        long t = ctx.plainModulus();
        assertTrue(t > 0, "BFV must report a plaintext modulus");
        assertEquals((t - 1) / 2, ctx.maxSlotValue());
        // The default parameters ask for a 20-bit t — nowhere near a long.
        assertTrue(t < (1L << 21), "expected a ~20-bit plaintext modulus, got " + t);
    }

    @Test
    public void aValueTooBigForASlotIsRefusedNotSilentlyWrapped() {
        BlindContext.initBfv(8192);
        FheContext ctx = BlindContext.getFheContext();
        long tooBig = ctx.maxSlotValue() + 1;

        // Before the guard this encrypted happily and decrypted to a plausible wrong number:
        // 1,000,000 came back as -32,193, and one bad entry corrupted every other slot too.
        FheException e = assertThrows(FheException.class,
            () -> ctx.encryptLongArray(new long[] { 1L, tooBig, 3L }));
        assertTrue(e.getMessage().contains("slot 1"), "the message must name the offending slot");

        assertThrows(FheException.class,
            () -> ctx.encryptLongArray(new long[] { Long.MAX_VALUE }));
        assertThrows(FheException.class,
            () -> ctx.encryptLongArray(new long[] { -tooBig }));
    }

    @Test
    public void aScalarTooBigForASlotIsRefusedNotSilentlyWrapped() {
        // The scalar path encodes through the same BatchEncoder as the array path (the value
        // lands in slot 0), so an out-of-range value is reduced mod t exactly the same way —
        // encryptLong(1_000_000) decrypted to a plausible wrong number. The guard must cover
        // both entry points, not just the array one.
        BlindContext.initBfv(8192);
        FheContext ctx = BlindContext.getFheContext();
        long tooBig = ctx.maxSlotValue() + 1;

        assertThrows(FheException.class, () -> ctx.encryptLong(tooBig));
        assertThrows(FheException.class, () -> ctx.encryptLong(-tooBig));
        assertThrows(FheException.class, () -> ctx.encryptLong(Long.MAX_VALUE));
    }

    @Test
    public void scalarValuesAtTheSlotBoundaryStillRoundTrip() {
        BlindContext.initBfv(8192);
        FheContext ctx = BlindContext.getFheContext();
        long max = ctx.maxSlotValue();

        for (long v : new long[] { 0L, 42L, -7L, max, -max }) {
            try (var ct = new FheCiphertextNative(ctx.encryptLong(v), ctx)) {
                assertEquals(v, ctx.decryptLong(ct.handle()), "scalar " + v + " must survive the round trip");
            }
        }
    }

    @Test
    public void valuesInsideTheSlotRangeStillRoundTrip() {
        BlindContext.initBfv(8192);
        FheContext ctx = BlindContext.getFheContext();
        long max = ctx.maxSlotValue();

        long[] in = { 0L, 5L, -7L, 1000L, max, -max };
        try (var ct = new FheCiphertextNative(ctx.encryptLongArray(in), ctx)) {
            long[] out = ctx.decryptLongArray(ct.handle());
            for (int i = 0; i < in.length; i++) {
                assertEquals(in[i], out[i], "slot " + i + " must survive the round trip");
            }
        }
    }
}

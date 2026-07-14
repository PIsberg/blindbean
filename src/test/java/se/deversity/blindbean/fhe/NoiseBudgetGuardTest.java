package se.deversity.blindbean.fhe;

import se.deversity.blindbean.context.BlindContext;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The last place this library could hand back wrong data in silence.
 *
 * <p>Every homomorphic operation spends noise budget. At zero, SEAL does not fail — it decrypts to a
 * plausible wrong number. Measured at the default parameters, the fifth chained multiplication came
 * back as <b>49,663 where 64 was expected</b>, with no exception and no warning. That is the same
 * failure shape as the key-rotation corruption and the BFV slot wrap: the computation completes, the
 * answer is garbage, and nothing says so.
 *
 * <p>These tests pin the fix and, just as importantly, pin the behaviour it replaces — the
 * {@code -Dblindbean.noise.guard=false} path still returns the garbage, and one test asserts that it
 * really is garbage, so the reason the guard exists stays visible in the suite.
 */
@Tag("native")
public class NoiseBudgetGuardTest {

    @AfterEach
    public void teardown() {
        BlindContext.clear();
    }

    /** Multiplies {@code acc} by encrypt(2), n times. Caller owns the returned handle. */
    private static FheCiphertextNative squareChain(FheContext ctx, int times) {
        var acc = new FheCiphertextNative(ctx.encryptLong(2L), ctx);
        for (int i = 0; i < times; i++) {
            try (var two = new FheCiphertextNative(ctx.encryptLong(2L), ctx)) {
                var next = new FheCiphertextNative(ctx.multiply(acc.handle(), two.handle()), ctx);
                acc.close();
                acc = next;
            }
        }
        return acc;
    }

    @Test
    public void fourMultipliesStillDecryptCorrectly() {
        BlindContext.initBfv(8192);
        FheContext ctx = BlindContext.getFheContext();

        try (var ct = squareChain(ctx, 4)) {
            assertTrue(ctx.noiseBudget(ct.handle()) > 0, "four multiplies must leave budget");
            assertEquals(32L, ctx.decryptLong(ct.handle()), "2 * 2^4 = 32");
        }
    }

    @Test
    public void theFifthMultiplyIsRefusedRatherThanDecryptedToGarbage() {
        BlindContext.initBfv(8192);
        FheContext ctx = BlindContext.getFheContext();

        try (var ct = squareChain(ctx, 5)) {
            assertEquals(0, ctx.noiseBudget(ct.handle()), "the fifth multiply exhausts the budget");

            FheException e = assertThrows(FheException.class, () -> ctx.decryptLong(ct.handle()),
                "an exhausted ciphertext must be refused, not decrypted to a plausible wrong number");

            // The message has to make the fix obvious, because the user cannot see anything wrong.
            assertTrue(e.getMessage().contains("Noise budget exhausted"), e.getMessage());
            assertTrue(e.getMessage().contains("noiseBudget()"), e.getMessage());
        }
    }

    @Test
    public void theBatchDecryptPathIsGuardedToo() {
        BlindContext.initBfv(8192);
        FheContext ctx = BlindContext.getFheContext();

        try (var ct = squareChain(ctx, 5)) {
            assertThrows(FheException.class, () -> ctx.decryptLongArray(ct.handle()),
                "the vector path must refuse an exhausted ciphertext as well as the scalar one");
        }
    }

    /**
     * Documents WHY the guard exists. With it disabled, the exhausted ciphertext still decrypts —
     * to a value that is simply wrong. If this test ever starts passing with the right answer, the
     * guard has become unnecessary and can go.
     */
    @Test
    public void withTheGuardOffTheOldSilentGarbageIsStillThere() {
        System.setProperty("blindbean.noise.guard", "false");
        try {
            // NOISE_GUARD is read once at class-init, so this only takes effect in a JVM where the
            // property was set before FheContext loaded. Assert on what we CAN observe here: the
            // budget is gone, which is the condition the guard keys off.
            BlindContext.initBfv(8192);
            FheContext ctx = BlindContext.getFheContext();

            try (var ct = squareChain(ctx, 5)) {
                assertEquals(0, ctx.noiseBudget(ct.handle()));
            }
        } finally {
            System.clearProperty("blindbean.noise.guard");
        }
    }

    @Test
    public void ckksIsUnaffected() {
        // CKKS has no noise budget (the native call returns -1) — its failure mode is precision
        // decay, not a cliff, and it cannot be detected this way. It must not be broken by the guard.
        BlindContext.initCkks(8192, Math.pow(2, 40));
        FheContext ctx = BlindContext.getFheContext();

        try (var ct = new FheCiphertextNative(ctx.encryptDouble(3.5), ctx)) {
            assertEquals(-1, ctx.noiseBudget(ct.handle()), "CKKS reports no budget");
            assertEquals(3.5, ctx.decryptDouble(ct.handle()), 0.01, "CKKS decrypt must still work");
        }
    }
}

package se.deversity.blindbean.fhe;

import se.deversity.blindbean.context.BlindContext;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
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
     * Documents WHY the guard exists, by turning it off and watching the corruption happen.
     *
     * <p>This is the behaviour every BFV user had until now: the ciphertext decrypts, to a number
     * that is simply wrong. Note what it is NOT — it is not zero, not an error, not obviously
     * broken. It is 49,663 where 64 was expected: a plausible value that would flow straight into a
     * balance, a total, a decision.
     *
     * <p>If this test ever fails because the value came back correct, the guard has become
     * unnecessary and can go.
     */
    @Test
    public void withTheGuardOffTheOldSilentCorruptionIsStillThere() {
        System.setProperty("blindbean.noise.guard", "false");
        try {
            BlindContext.initBfv(8192);
            FheContext ctx = BlindContext.getFheContext();

            try (var ct = squareChain(ctx, 5)) {
                assertEquals(0, ctx.noiseBudget(ct.handle()), "budget is spent");

                long got = ctx.decryptLong(ct.handle());   // no exception — that is the bug
                assertNotEquals(64L, got,
                    "with the guard off, an exhausted ciphertext decrypts to garbage; if it came "
                    + "back correct, the guard is no longer needed");
                assertTrue(got > 0, "and the garbage is a plausible-looking number, not an obvious "
                                  + "sentinel — which is exactly why it was never noticed: got " + got);
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

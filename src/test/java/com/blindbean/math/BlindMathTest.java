package com.blindbean.math;

import com.blindbean.annotations.Scheme;
import com.blindbean.core.Ciphertext;
import com.blindbean.context.BlindContext;
import com.blindbean.fhe.FheCiphertextNative;
import com.blindbean.fhe.FheContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

public class BlindMathTest {

    @AfterEach
    public void teardown() {
        BlindContext.clear();
    }

    // ================================================================
    // Paillier Tests (unchanged from original)
    // ================================================================
    @Nested
    class PaillierTests {

        @BeforeEach
        public void setup() {
            BlindContext.init();
        }

        @Test
        public void testPaillierAddition() {
            PaillierMath paillier = BlindContext.getPaillier();

            BigInteger a = BigInteger.valueOf(150);
            BigInteger b = BigInteger.valueOf(250);

            Ciphertext cA = paillier.encrypt(a);
            Ciphertext cB = paillier.encrypt(b);

            // Decrypt(Encrypt(A) + Encrypt(B)) == A + B
            Ciphertext cSum = BlindMath.add(cA, cB);
            BigInteger result = paillier.decrypt(cSum);

            assertEquals(BigInteger.valueOf(400), result);
        }
    }

    // ================================================================
    // BFV FHE Tests — through BlindMath dispatcher
    // ================================================================
    @Nested
    class BfvDispatchTests {

        @BeforeEach
        public void setup() {
            BlindContext.initBfv(8192);
        }

        @Test
        public void testBfvAdditionThroughBlindMath() {
            FheContext ctx = BlindContext.getFheContext();

            // Create Ciphertext records via the native bridge
            try (var ctA = new FheCiphertextNative(ctx.encryptLong(150L), ctx);
                 var ctB = new FheCiphertextNative(ctx.encryptLong(250L), ctx)) {

                Ciphertext a = ctA.toBlindCiphertext();
                Ciphertext b = ctB.toBlindCiphertext();

                // This goes through BlindMath.add → fheAdd dispatch
                Ciphertext sum = BlindMath.add(a, b);

                // Verify by deserializing and decrypting
                try (var ctResult = FheCiphertextNative.fromBlindCiphertext(ctx, sum)) {
                    long result = ctx.decryptLong(ctResult.handle());
                    assertEquals(400L, result);
                }
            }
        }

        @Test
        public void testBfvMultiplicationThroughBlindMath() {
            FheContext ctx = BlindContext.getFheContext();

            try (var ctA = new FheCiphertextNative(ctx.encryptLong(12L), ctx);
                 var ctB = new FheCiphertextNative(ctx.encryptLong(5L), ctx)) {

                Ciphertext a = ctA.toBlindCiphertext();
                Ciphertext b = ctB.toBlindCiphertext();

                Ciphertext product = BlindMath.multiply(a, b);

                try (var ctResult = FheCiphertextNative.fromBlindCiphertext(ctx, product)) {
                    long result = ctx.decryptLong(ctResult.handle());
                    assertEquals(60L, result);
                }
            }
        }

        @Test
        public void testRealNoiseBudget() {
            FheContext ctx = BlindContext.getFheContext();
            var ct = ctx.encryptLong(5L);

            int budget = ctx.noiseBudget(ct);
            assertTrue(budget > 0, "Real noise budget must be positive, got: " + budget);
            assertNotEquals(80, budget, "Budget should be a real SEAL value, not the old hardcoded dummy 80");

            // After multiplication, budget drops significantly
            var ctSq = ctx.multiply(ct, ct);
            int afterMul = ctx.noiseBudget(ctSq);
            assertTrue(afterMul < budget,
                    "Budget should drop after multiply: " + budget + " → " + afterMul);

            if (afterMul < 10) {
                System.err.println("[WARN] FHE Noise Budget is critically low (" + afterMul +
                        " bits). Further operations may produce incorrect results.");
            }

            ctx.freeCiphertext(ct);
            ctx.freeCiphertext(ctSq);
        }
    }

    // ================================================================
    // Cross-Scheme Error Tests
    // ================================================================
    @Nested
    class CrossSchemeTests {

        @BeforeEach
        public void setup() {
            BlindContext.init(); // Paillier
        }

        @Test
        public void testCannotAddDifferentSchemes() {
            PaillierMath paillier = BlindContext.getPaillier();
            Ciphertext paillierCt = paillier.encrypt(BigInteger.valueOf(10));
            Ciphertext fakeBfv = new Ciphertext("deadbeef", Scheme.BFV);

            assertThrows(IllegalArgumentException.class,
                    () -> BlindMath.add(paillierCt, fakeBfv));
        }

        @Test
        public void testPaillierMultiplyUnsupported() {
            PaillierMath paillier = BlindContext.getPaillier();
            Ciphertext a = paillier.encrypt(BigInteger.valueOf(3));
            Ciphertext b = paillier.encrypt(BigInteger.valueOf(4));

            assertThrows(UnsupportedOperationException.class,
                    () -> BlindMath.multiply(a, b));
        }
    }
}

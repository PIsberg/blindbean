package com.blindbean.fhe;

import com.blindbean.context.BlindContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.lang.foreign.MemorySegment;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive tests for the SEAL-backed FheNativeBridge.
 * Exercises BFV (exact integer), CKKS (approximate real), serialization,
 * noise budget diagnostics, and resource management.
 */
public class FheNativeBridgeTest {

    @AfterEach
    public void teardown() {
        BlindContext.clear();
    }

    // ================================================================
    // BFV Tests — Exact Integer Arithmetic
    // ================================================================
    @Nested
    class BfvTests {

        @BeforeEach
        void initBfv() {
            BlindContext.initBfv(8192);
        }

        @Test
        public void testBfvEncryptDecryptRoundTrip() {
            try (var ctx = BlindContext.getFheContext()) {
                MemorySegment ct = ctx.encryptLong(42L);
                long result = ctx.decryptLong(ct);
                assertEquals(42L, result);
                ctx.freeCiphertext(ct);
            }
        }

        @Test
        public void testBfvAddition() {
            try (var ctx = BlindContext.getFheContext()) {
                MemorySegment ctA = ctx.encryptLong(100L);
                MemorySegment ctB = ctx.encryptLong(300L);
                MemorySegment ctSum = ctx.add(ctA, ctB);

                long sum = ctx.decryptLong(ctSum);
                assertEquals(400L, sum);

                ctx.freeCiphertext(ctA);
                ctx.freeCiphertext(ctB);
                ctx.freeCiphertext(ctSum);
            }
        }

        @Test
        public void testBfvMultiplication() {
            try (var ctx = BlindContext.getFheContext()) {
                MemorySegment ctA = ctx.encryptLong(7L);
                MemorySegment ctB = ctx.encryptLong(8L);
                MemorySegment ctProd = ctx.multiply(ctA, ctB);

                long product = ctx.decryptLong(ctProd);
                assertEquals(56L, product);

                ctx.freeCiphertext(ctA);
                ctx.freeCiphertext(ctB);
                ctx.freeCiphertext(ctProd);
            }
        }

        @Test
        public void testBfvNoiseBudgetDecreases() {
            try (var ctx = BlindContext.getFheContext()) {
                MemorySegment ct = ctx.encryptLong(5L);
                int initialBudget = ctx.noiseBudget(ct);
                assertTrue(initialBudget > 0, "Initial noise budget should be positive");

                // Multiplication consumes more noise budget than addition
                MemorySegment ctSq = ctx.multiply(ct, ct);
                int afterMultiply = ctx.noiseBudget(ctSq);
                assertTrue(afterMultiply < initialBudget,
                        "Noise budget should decrease after multiplication: " +
                        initialBudget + " → " + afterMultiply);

                ctx.freeCiphertext(ct);
                ctx.freeCiphertext(ctSq);
            }
        }

        @Test
        public void testBfvZeroValue() {
            try (var ctx = BlindContext.getFheContext()) {
                MemorySegment ct = ctx.encryptLong(0L);
                long result = ctx.decryptLong(ct);
                assertEquals(0L, result);
                ctx.freeCiphertext(ct);
            }
        }

        @Test
        public void testBfvNegativeValue() {
            try (var ctx = BlindContext.getFheContext()) {
                // BFV with BatchEncoder and modular arithmetic supports negative values
                MemorySegment ct = ctx.encryptLong(-42L);
                long result = ctx.decryptLong(ct);
                assertEquals(-42L, result);
                ctx.freeCiphertext(ct);
            }
        }
    }

    // ================================================================
    // CKKS Tests — Approximate Real Arithmetic
    // ================================================================
    @Nested
    class CkksTests {

        private static final double CKKS_TOLERANCE = 0.001;

        @BeforeEach
        void initCkks() {
            BlindContext.initCkks(8192, Math.pow(2, 40));
        }

        @Test
        public void testCkksEncryptDecryptRoundTrip() {
            try (var ctx = BlindContext.getFheContext()) {
                MemorySegment ct = ctx.encryptDouble(3.14159);
                double result = ctx.decryptDouble(ct);
                assertEquals(3.14159, result, CKKS_TOLERANCE);
                ctx.freeCiphertext(ct);
            }
        }

        @Test
        public void testCkksAddition() {
            try (var ctx = BlindContext.getFheContext()) {
                MemorySegment ctA = ctx.encryptDouble(1.5);
                MemorySegment ctB = ctx.encryptDouble(2.7);
                MemorySegment ctSum = ctx.add(ctA, ctB);

                double sum = ctx.decryptDouble(ctSum);
                assertEquals(4.2, sum, CKKS_TOLERANCE);

                ctx.freeCiphertext(ctA);
                ctx.freeCiphertext(ctB);
                ctx.freeCiphertext(ctSum);
            }
        }

        @Test
        public void testCkksNoiseBudgetReturnsNegativeOne() {
            try (var ctx = BlindContext.getFheContext()) {
                MemorySegment ct = ctx.encryptDouble(1.0);
                int budget = ctx.noiseBudget(ct);
                assertEquals(-1, budget, "CKKS noise budget should return -1");
                ctx.freeCiphertext(ct);
            }
        }
    }

    // ================================================================
    // Serialization Tests
    // ================================================================
    @Nested
    class SerializationTests {

        @BeforeEach
        void initBfv() {
            BlindContext.initBfv(8192);
        }

        @Test
        public void testSerializationRoundTrip() {
            try (var ctx = BlindContext.getFheContext()) {
                MemorySegment ct = ctx.encryptLong(12345L);

                // Serialize to bytes via FheCiphertextNative
                try (var nativeCt = new FheCiphertextNative(ct, ctx)) {
                    byte[] serialized = nativeCt.serialize();
                    assertTrue(serialized.length > 0, "Serialized ciphertext should not be empty");

                    // Deserialize into a new ciphertext
                    try (var restored = FheCiphertextNative.deserialize(ctx, serialized)) {
                        long result = ctx.decryptLong(restored.handle());
                        assertEquals(12345L, result);
                    }
                }
            }
        }
    }

    // ================================================================
    // Resource Management Tests
    // ================================================================
    @Nested
    class ResourceManagementTests {

        @Test
        public void testFheContextAutoClose() {
            // Explicit close — should not throw
            FheContext ctx = FheContext.bfv(4096);
            MemorySegment ct = ctx.encryptLong(1L);
            ctx.freeCiphertext(ct);
            ctx.close();

            // Operations after close should throw
            assertThrows(FheException.class, () -> ctx.encryptLong(2L));
        }

        @Test
        public void testTryWithResources() {
            // Should clean up without exceptions
            assertDoesNotThrow(() -> {
                try (var ctx = FheContext.bfv(4096)) {
                    MemorySegment ct = ctx.encryptLong(99L);
                    long val = ctx.decryptLong(ct);
                    assertEquals(99L, val);
                    ctx.freeCiphertext(ct);
                }
            });
        }
    }

    // ================================================================
    // Error Handling Tests
    // ================================================================
    @Nested
    class ErrorTests {

        @Test
        public void testWrongSchemeEncryptLong() {
            BlindContext.initCkks(8192, Math.pow(2, 40));
            try (var ctx = BlindContext.getFheContext()) {
                // Attempting BFV encrypt on CKKS context should throw
                assertThrows(FheException.class, () -> ctx.encryptLong(42L));
            }
        }

        @Test
        public void testWrongSchemeEncryptDouble() {
            BlindContext.initBfv(8192);
            try (var ctx = BlindContext.getFheContext()) {
                // Attempting CKKS encrypt on BFV context should throw
                assertThrows(FheException.class, () -> ctx.encryptDouble(3.14));
            }
        }

        @Test
        public void testNoContextInitialized() {
            assertThrows(FheException.class, BlindContext::getFheContext);
        }
    }
}

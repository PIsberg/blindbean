package com.blindbean.math;

import com.github.asynctest.AsyncTest;
import org.junit.jupiter.api.Test;

import java.util.concurrent.ThreadLocalRandom;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * Concurrency stress tests for pure math and SIMD components.
 */
class MathAsyncConcurrencyTest {

    // ── 1. Vectorized Batch Add Safety ────────────────────────────────────

    /**
     * Stresses the Vector API parallel batch sum logic.
     * While the method itself is stateless, this confirms that concurrent calls
     * from virtual threads do not experience register corruption or side-effects.
     */
    @AsyncTest(
        threads = 24,
        invocations = 100,
        detectRaceConditions = true,
        detectVisibility = true
    )
    void vectorizedBatchAddIsThreadSafe() {
        int len = 8192;
        long[] c1 = new long[len];
        long[] c2 = new long[len];
        long[] result = new long[len];
        long modN2 = 987654321012345L;

        for (int i = 0; i < len; i++) {
            c1[i] = ThreadLocalRandom.current().nextLong(1000);
            c2[i] = ThreadLocalRandom.current().nextLong(1000);
        }

        PaillierVectorized.batchAdd(c1, c2, result, modN2);

        // Spot check a few result indices
        for (int i = 0; i < 100; i++) {
            int idx = ThreadLocalRandom.current().nextInt(len);
            assertEquals((c1[idx] * c2[idx]) % modN2, result[idx], 
                "SIMD result must match sequential baseline at index " + idx);
        }
    }

    private void assertEquals(long expected, long actual, String message) {
        if (expected != actual) {
            throw new AssertionError(message + " (expected: " + expected + ", actual: " + actual + ")");
        }
    }
}

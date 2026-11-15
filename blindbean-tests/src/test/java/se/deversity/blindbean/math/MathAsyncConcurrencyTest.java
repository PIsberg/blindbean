package se.deversity.blindbean.math;

import se.deversity.asynctest.AsyncTest;
import se.deversity.asynctest.Preset;
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
    // The detectors are off here (Preset.NONE): batchAdd is a stateless pure function over
    // caller-owned arrays, so there is no cross-thread race for them to find, and this test is the
    // N x M stress execution alone.
    //
    // The JDK 26 Windows leg failed here on 2026-08-01 and again on 2026-11-15, the second time
    // with the detectors already off, so instrumentation was not the cause: batchAdd's vector
    // range check refused an in-range operand at index 8002. That check is now a scalar loop
    // (see PaillierVectorized.requireReduced). The SIMD arithmetic still uses vector compares, so
    // every index is checked below rather than a sample, and a failure names the platform.
    @AsyncTest(
        threads = 24,
        invocations = 100,
        preset = Preset.NONE
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

        for (int idx = 0; idx < len; idx++) {
            long expected = (c1[idx] * c2[idx]) % modN2;
            if (result[idx] != expected) {
                throw new AssertionError("SIMD result must match sequential baseline at index " + idx
                    + " (expected: " + expected + ", actual: " + result[idx] + "; java "
                    + System.getProperty("java.vm.version") + ", " + System.getProperty("os.name")
                    + " " + System.getProperty("os.arch") + ", "
                    + jdk.incubator.vector.LongVector.SPECIES_PREFERRED.length() + " lanes)");
            }
        }
    }
}

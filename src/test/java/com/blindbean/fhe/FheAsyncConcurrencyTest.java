package com.blindbean.fhe;

import com.blindbean.annotations.Scheme;
import com.blindbean.async.BlindAsync;
import com.blindbean.context.BlindContext;
import com.github.asynctest.AsyncTest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;

import java.lang.foreign.MemorySegment;
import java.util.concurrent.ThreadLocalRandom;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Concurrency stress tests for FHE native components.
 */
class FheAsyncConcurrencyTest {

    private volatile FheContext bfvContext;

    @BeforeEach
    void setup() {
        BlindAsync.shutdown();
        BlindContext.init();
        // Initialize a shared BFV context for stress testing
        bfvContext = FheContext.bfv(8192);
    }

    @AfterEach
    void teardown() {
        if (bfvContext != null) {
            try {
                bfvContext.close();
            } catch (Exception ignored) {}
        }
        BlindAsync.shutdown();
        BlindContext.clear();
    }

    // ── 1. Shared Context Stress ──────────────────────────────────────────

    /**
     * Hammers a single shared FheContext with concurrent BFV operations.
     * Verifies that the internal nativeLock correctly serializes access to the
     * non-thread-safe SEAL pointers.
     */
    @AsyncTest(
        threads = 20,
        invocations = 100,
        detectRaceConditions = true,
        detectAtomicityViolations = true,
        timeoutMs = 60000
    )
    void concurrentBfvOperationsAreThreadSafe() {
        long val1 = ThreadLocalRandom.current().nextLong(1000);
        long val2 = ThreadLocalRandom.current().nextLong(1000);

        MemorySegment ct1 = bfvContext.encryptLong(val1);
        MemorySegment ct2 = bfvContext.encryptLong(val2);

        MemorySegment sumCt = bfvContext.add(ct1, ct2);
        long result = bfvContext.decryptLong(sumCt);

        assertEquals(val1 + val2, result, "Homomorphic addition must be correct under stress");

        bfvContext.freeCiphertext(ct1);
        bfvContext.freeCiphertext(ct2);
        bfvContext.freeCiphertext(sumCt);
    }

    // ── 2. Concurrent Close Safety ────────────────────────────────────────

    /**
     * Multiple threads simultaneously call close() on the SAME context.
     * Verifies that the 'closed' volatile flag and the structure of close() 
     * prevents double-frees or native crashes.
     */
    @AsyncTest(
        threads = 10,
        invocations = 50,
        detectRaceConditions = true
    )
    void concurrentCloseIsSafe() {
        // Each thread tries to close the SAME shared context
        bfvContext.close();
    }

    // ── 3. Simultaneous Key Export ────────────────────────────────────────

    /**
     * Stresses the native buffer allocation and serialization logic in exportState.
     */
    @AsyncTest(
        threads = 15,
        invocations = 30,
        detectRaceConditions = true,
        timeoutMs = 30000
    )
    void simultaneousKeyExport() {
        byte[] state = bfvContext.exportState();
        assertNotNull(state);
        assertTrue(state.length > 0);
    }

    // ── 4. Mixed Arena Stress ─────────────────────────────────────────────

    /**
     * Rapidly creates and closes contexts, each using Arena.ofShared().
     * Tests if there is any cross-context interference in the native bridge.
     */
    @AsyncTest(
        threads = 10,
        invocations = 20,
        detectResourceLeaks = true,
        timeoutMs = 45000
    )
    void rapidContextCreationAndCleanup() {
        try (FheContext ctx = FheContext.bfv(4096)) {
            MemorySegment ct = ctx.encryptLong(42L);
            assertEquals(42L, ctx.decryptLong(ct));
            ctx.freeCiphertext(ct);
        }
    }
}

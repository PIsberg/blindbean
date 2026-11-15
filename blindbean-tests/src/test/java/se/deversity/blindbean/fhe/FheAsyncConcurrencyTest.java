package se.deversity.blindbean.fhe;

import se.deversity.blindbean.annotations.Scheme;
import se.deversity.blindbean.async.BlindAsync;
import se.deversity.blindbean.context.BlindContext;
import se.deversity.asynctest.AsyncTest;
import se.deversity.asynctest.DetectorType;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;

import java.lang.foreign.MemorySegment;
import java.util.concurrent.ThreadLocalRandom;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Concurrency stress tests for FHE native components.
 */
@Tag("native")
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
     *
     * <p>{@code timeoutMs} is the budget for all rounds together, not per round. Every body runs
     * fully serialized on {@code nativeLock}, so 100 rounds of 20 threads (2,000 bodies at about
     * 22 ms) took 43.7 s of the 60 s in a green local run and crossed it under load: the failure
     * read "round timed out: 4/20 threads completed within 186ms", the last round starting with
     * 186 ms of budget left (#259). 30 rounds keep 600 colliding bodies at about a quarter of the
     * budget. More rounds bought nothing measurable: with the lock removed from encryptLong, add
     * and decryptLong this test passed at 30 and at 100 rounds alike, so it does not yet detect a
     * missing lock (#268).
     */
    @AsyncTest(
        threads = 20,
        invocations = 30,
        timeoutMs = 60000,
        includes = { DetectorType.RACE_CONDITIONS, DetectorType.ATOMICITY_VIOLATIONS }
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
        includes = DetectorType.RACE_CONDITIONS
    )
    void concurrentCloseIsSafe() {
        // Each thread tries to close the SAME shared context
        bfvContext.close();
    }

    // ── 3. Simultaneous Key Export ────────────────────────────────────────

    /**
     * Stresses the native buffer allocation and serialization logic in exportState.
     *
     * <p>450 full SEAL key exports (15 x 30), each serializing the secret, public and relin keys
     * of an 8192-degree context. That is genuinely slow work: the old 30s budget was clearing by a
     * hair and tipped over under load, so it gets the same 60s the sibling stress test uses.
     */
    @AsyncTest(
        threads = 15,
        invocations = 30,
        timeoutMs = 60000,
        includes = { DetectorType.RACE_CONDITIONS, DetectorType.RESOURCE_LEAKS }
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
        timeoutMs = 45000,
        includes = DetectorType.RESOURCE_LEAKS
    )
    void rapidContextCreationAndCleanup() {
        try (FheContext ctx = FheContext.bfv(4096)) {
            MemorySegment ct = ctx.encryptLong(42L);
            assertEquals(42L, ctx.decryptLong(ct));
            ctx.freeCiphertext(ct);
        }
    }
}

package com.blindbean.async;

import com.blindbean.context.BlindContext;
import com.blindbean.core.Ciphertext;
import com.blindbean.math.PaillierMath;
import com.github.asynctest.AsyncTest;
import com.github.asynctest.BeforeEachInvocation;
import com.github.asynctest.DetectorType;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;

import java.math.BigInteger;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Concurrent stress tests for BlindAsync and its dependencies using async-test-lib.
 *
 * Each @AsyncTest launches all threads simultaneously through a CyclicBarrier,
 * forcing real thread collisions that sequential @Test runs miss.
 *
 * Coverage:
 *   1. Executor DCL initialization race
 *   2. Semaphore permit release on exception
 *   3. BlindContext snapshot propagation correctness
 *   4. Virtual-thread carrier pinning
 *   5. Concurrent CompletableFuture fan-out (no leaked futures)
 *   6. PaillierMath thread-safety under high contention
 */
class BlindAsyncConcurrencyTest {

    @BeforeEach
    void setup() {
        BlindAsync.shutdown(); // each test method starts with a fresh executor
        BlindContext.init();
    }

    @AfterEach
    void teardown() {
        BlindAsync.shutdown();
        BlindContext.clear();
    }

    // ── 1. Executor DCL initialization ────────────────────────────────────

    /**
     * All 50 threads hit executor() simultaneously on invocation 1 (post-shutdown).
     * The volatile + double-checked locking pattern in BlindAsync.executor() must
     * survive without races or stale reads.
     */
    @AsyncTest(
        threads = 50,
        invocations = 20,
        detectDoubleCheckedLocking = true,
        detectRaceConditions = true,
        detectVisibility = true
    )
    void executorInitializationNeverRaces() {
        BlindAsync.runAsync(() -> {}).join();
    }

    // ── 2. Semaphore permit integrity on exception ─────────────────────────

    /**
     * ~20% of submitted tasks throw a RuntimeException. The finally block inside
     * BlindAsync must always release the semaphore permit regardless. A permit leak
     * would starve subsequent tasks and cause a test timeout.
     */
    @AsyncTest(
        threads = 20,
        invocations = 100,
        monitorSemaphore = true,
        detectCompletableFutureExceptions = true,
        detectInterruptMishandling = true,
        timeoutMs = 8000
    )
    void semaphorePermitsAlwaysReleasedOnException() {
        BlindAsync.runAsync(() -> {
            if (ThreadLocalRandom.current().nextInt(5) == 0) {
                throw new IllegalStateException("intentional task failure");
            }
        }).exceptionally(ignored -> null).join();
    }

    // ── 3. BlindContext snapshot propagation correctness ──────────────────

    /**
     * Every concurrent thread initializes its own Paillier context, submits a
     * runAsync task, and asserts the virtual thread received exactly its context —
     * not a stale or different thread's snapshot.
     *
     * Exercises the snapshot-capture-before-dispatch path in BlindAsync.runAsync().
     */
    @AsyncTest(
        threads = 20,
        invocations = 100,
        detectRaceConditions = true
    )
    void contextSnapshotPropagatedToCorrectVirtualThread() throws Exception {
        BlindContext.init(); // each concurrent thread initializes its own ThreadLocal context
        PaillierMath local = BlindContext.getPaillier();

        AtomicReference<PaillierMath> asyncMath = new AtomicReference<>();
        BlindAsync.runAsync(() -> asyncMath.set(BlindContext.getPaillier())).get();

        assertSame(local, asyncMath.get(),
                "Virtual thread must receive exactly the caller's PaillierMath, not another thread's");
        BlindContext.clear();
    }

    // ── 4. Virtual-thread pinning ─────────────────────────────────────────

    /**
     * Verifies that BlindAsync's runAsync lambda does not pin its virtual thread to
     * the carrier platform thread. Pinning would break scalability and defeat the
     * purpose of virtual threads.
     *
     * Semaphore.acquireUninterruptibly() parks via LockSupport — must not pin.
     * BlindContext.restore() uses ThreadLocal.set() — must not pin.
     *
     * Note: virtualThreadStressMode is intentionally OFF. HIGH/EXTREME modes pin
     * all carrier threads, which causes the semaphore's virtual-thread park to stall
     * (no free carrier to resume on) — that is a stress-mode effect, not a bug in
     * our code. OFF lets the pinning *detector* run cleanly on real work.
     */
    @AsyncTest(
        threads = 20,
        invocations = 50,
        useVirtualThreads = true,
        virtualThreadStressMode = "OFF",
        detectVirtualThreadPinning = true,
        timeoutMs = 15000
    )
    void runAsyncDoesNotPinCarrierThread() {
        BlindAsync.supplyAsync(() -> BigInteger.TWO).join();
    }

    // ── 5. Concurrent fan-out: no leaked or abandoned futures ─────────────

    /**
     * Fans out 3 concurrent runAsync tasks per test-thread, all of which must
     * complete. A future that is submitted but never completed would deadlock
     * or timeout — caught by the completion-leak detector.
     */
    @AsyncTest(
        threads = 10,
        invocations = 50,
        detectCompletableFutureCompletionLeaks = true,
        detectCompletableFutureExceptions = true,
        detectResourceLeaks = true
    )
    void fanOutFuturesAlwaysComplete() {
        CompletableFuture.allOf(
            BlindAsync.runAsync(() -> {}),
            BlindAsync.runAsync(() -> {}),
            BlindAsync.runAsync(() -> {})
        ).join();
    }

    // ── 6. PaillierMath concurrent encrypt / decrypt ───────────────────────

    /**
     * Hammers PaillierMath.encrypt() and decrypt() from 20 concurrent threads.
     * PaillierMath is designed thread-safe (immutable key pair, SecureRandom per call).
     * This confirms no latent race or atomicity violation exists at high contention.
     */
    @AsyncTest(
        threads = 20,
        invocations = 200,
        detectRaceConditions = true,
        detectAtomicityViolations = true
    )
    void paillierEncryptDecryptIsThreadSafe() {
        long raw = ThreadLocalRandom.current().nextLong(1_000_000L);
        BigInteger original = BigInteger.valueOf(raw);
        PaillierMath paillier = BlindContext.getPaillier();
        Ciphertext ct = paillier.encrypt(original);
        assertEquals(original, paillier.decrypt(ct));
    }

    // ── 7. Snapshot / restore round-trip under concurrent BlindContext.init ─

    /**
     * Concurrent threads each initialize their own context, capture a snapshot,
     * immediately restore it onto the same thread, and re-read the context.
     * Verifies restore() never clobbers another thread's state via the ThreadLocal.
     */
    @AsyncTest(
        threads = 30,
        invocations = 100,
        detectRaceConditions = true
    )
    void snapshotRestoreRoundTripIsIsolated() {
        BlindContext.init();
        PaillierMath before = BlindContext.getPaillier();

        BlindContext.Snapshot snap = BlindContext.snapshot();
        BlindContext.clear();
        BlindContext.restore(snap);

        assertSame(before, BlindContext.getPaillier(),
                "restore() must put back exactly the snapshotted PaillierMath");
        BlindContext.clear();
    }

    // ── 8. Executor churn: simultaneous shutdown and re-init ──────────────

    /**
     * Stresses the atomic re-initialization of the virtual executor and its 
     * companion semaphore. Multiple threads racing to shutdown() while others 
     * call runAsync() must not result in NullPointerException or double-initialized 
     * semaphores (leaking permits).
     */
    @AsyncTest(
        threads = 50,
        invocations = 50,
        detectRaceConditions = true,
        detectVisibility = true
    )
    void churnExecutorShutdownAndInit() {
        if (ThreadLocalRandom.current().nextBoolean()) {
            BlindAsync.shutdown();
        } else {
            BlindAsync.runAsync(() -> {}).join();
        }
    }

    // ── 9. Permit integrity under high contention ─────────────────────────

    /**
     * Submits 100 concurrent tasks when only few permits (CPU cores) are available.
     * All tasks must eventually complete. If a permit is hung or leaked, the 
     * CompletableFuture completion leak detector will fire.
     */
    @AsyncTest(
        threads = 100,
        invocations = 10,
        detectCompletableFutureCompletionLeaks = true,
        timeoutMs = 15000
    )
    void permitHoggingDoesNotPreventFutureCompletion() {
        BlindAsync.runAsync(() -> {
            // simulate brief CPU work
            BigInteger.valueOf(123456789L).pow(100);
        }).join();
    }
}

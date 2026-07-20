package se.deversity.blindbean.async;

import se.deversity.blindbean.context.BlindContext;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.Semaphore;
import java.util.function.Supplier;

import org.jspecify.annotations.Nullable;

import se.deversity.vibetags.annotations.AIAudit;
import se.deversity.vibetags.annotations.AIFeatureFlag;
import se.deversity.vibetags.annotations.AIIgnore;
import se.deversity.vibetags.annotations.AIParallelTests;
import se.deversity.vibetags.annotations.AIThreadSafe;

/**
 * Virtual-thread dispatcher for async BlindBean wrapper operations.
 *
 * <p>All submitted tasks run on Java 26 virtual threads. A {@link Semaphore} capped at
 * {@code Runtime.availableProcessors()} permits prevents CPU thrashing — FHE operations are
 * CPU-bound, so unbounded parallelism on an N-core machine degrades throughput. Virtual threads
 * park cheaply on the semaphore, so callers may enqueue far more tasks than available cores
 * without blocking platform threads.
 *
 * <p>The caller thread's {@link BlindContext} is captured as a {@link BlindContext.Snapshot}
 * before dispatch and re-installed on the virtual thread, solving the {@link ThreadLocal}
 * propagation gap across thread boundaries.
 *
 * <p>The executor and its companion semaphore live in a single immutable {@link State} holder
 * behind one volatile field, so a reader can never observe one without the other. The state is
 * lazily initialized on first use (double-checked locking); sync-only users pay no
 * initialization cost. Call {@link #shutdown()} in tests or application teardown.
 *
 * <p>Dispatch is guaranteed even while {@link #shutdown()} is being called concurrently: an
 * optimistic submission outside the lock is retried once under the init monitor, where the
 * freshly created executor cannot be closed before the task is accepted — and
 * {@link ExecutorService#close()} waits for accepted tasks, so the task always runs.
 */
@AIThreadSafe(strategy = AIThreadSafe.Strategy.OTHER,
              note = "Executor + semaphore held as one immutable State behind a single volatile (DCL lazy init); "
                   + "CPU-bound semaphore serializes FHE tasks across virtual threads; shutdown races resolved by "
                   + "re-submitting under the init monitor, which shutdown() must also acquire")
@AIAudit(checkFor = {"Thread Safety", "Resource Leaks", "Shutdown race conditions"})
@AIParallelTests
@AIFeatureFlag(flag = "blindbean.apt.async", defaultValue = false)
public final class BlindAsync {

    /**
     * Historical retry bound from the attempt-counting dispatcher. Dispatch no longer gives
     * up — a lost shutdown race is resolved by re-submitting under the init monitor — so this
     * constant is retained only for backward compatibility and is no longer consulted.
     */
    public static final int MAX_ATTEMPTS = 3;

    /** Immutable pairing of the executor and its semaphore — readers see both or neither. */
    private record State(ExecutorService executor, Semaphore semaphore) {}

    private static volatile @Nullable State state;
    /** Guarded by the init monitor; the JVM shutdown hook survives executor recycling, so register it once. */
    private static boolean shutdownHookRegistered;
    @AIIgnore(reason = "Internal DCL synchronization monitor — not relevant to AI-assisted development workflows")
    private static final Object INIT_LOCK = new Object();

    private BlindAsync() {}

    // ── Lazy initialization ───────────────────────────────────────────────

    private static State state() {
        State s = state; // read volatile once into local
        if (s == null) {
            synchronized (INIT_LOCK) {
                s = state;
                if (s == null) {
                    s = state = new State(
                            Executors.newVirtualThreadPerTaskExecutor(),
                            new Semaphore(Runtime.getRuntime().availableProcessors()));
                    if (!shutdownHookRegistered) {
                        Runtime.getRuntime().addShutdownHook(new Thread(BlindAsync::shutdown, "blindbean-async-shutdown"));
                        shutdownHookRegistered = true;
                    }
                }
            }
        }
        return s; // always return the local — never re-reads the volatile
    }

    // ── Public API ────────────────────────────────────────────────────────

    /**
     * Runs {@code task} asynchronously on a virtual thread with the current thread's
     * {@link BlindContext} available.
     *
     * @param task a mutating wrapper operation (e.g., {@code wrapper::encryptBalance})
     * @return a {@link CompletableFuture} that completes when the task finishes
     */
    public static CompletableFuture<Void> runAsync(Runnable task) {
        BlindContext.Snapshot snapshot = BlindContext.snapshot();
        try {
            return dispatchRun(task, snapshot, state());
        } catch (RejectedExecutionException raced) {
            // shutdown() closed the executor between state() and submission. Re-submit while
            // holding the init monitor: shutdown() must also acquire it, so the (possibly fresh)
            // executor observed here cannot be closed before the task is accepted.
            synchronized (INIT_LOCK) {
                return dispatchRun(task, snapshot, state());
            }
        }
    }

    /**
     * Supplies a value asynchronously on a virtual thread with the current thread's
     * {@link BlindContext} available.
     *
     * @param task a reading wrapper operation (e.g., {@code wrapper::decryptBalance})
     * @param <T>  the result type
     * @return a {@link CompletableFuture} that completes with the task's return value
     */
    public static <T> CompletableFuture<T> supplyAsync(Supplier<T> task) {
        BlindContext.Snapshot snapshot = BlindContext.snapshot();
        try {
            return dispatchSupply(task, snapshot, state());
        } catch (RejectedExecutionException raced) {
            synchronized (INIT_LOCK) {
                return dispatchSupply(task, snapshot, state());
            }
        }
    }

    private static CompletableFuture<Void> dispatchRun(Runnable task, BlindContext.Snapshot snapshot, State s) {
        return CompletableFuture.runAsync(() -> {
            s.semaphore().acquireUninterruptibly(); // s is immutable — acquire and release hit the same instance
            try {
                BlindContext.restore(snapshot);
                task.run();
            } finally {
                s.semaphore().release();
            }
        }, s.executor());
    }

    private static <T> CompletableFuture<T> dispatchSupply(Supplier<T> task, BlindContext.Snapshot snapshot, State s) {
        return CompletableFuture.supplyAsync(() -> {
            s.semaphore().acquireUninterruptibly(); // s is immutable — acquire and release hit the same instance
            try {
                BlindContext.restore(snapshot);
                return task.get();
            } finally {
                s.semaphore().release();
            }
        }, s.executor());
    }

    /**
     * Shuts down the internal executor, waiting for already-accepted tasks to finish.
     * Safe to call multiple times. Subsequent calls to {@link #runAsync} or
     * {@link #supplyAsync} will reinitialize it.
     */
    public static void shutdown() {
        State toClose;
        synchronized (INIT_LOCK) {
            toClose = state;
            state = null; // null before close() so concurrent callers reinitialize instead of racing the close
        }
        if (toClose != null) {
            toClose.executor().close();
        }
    }
}

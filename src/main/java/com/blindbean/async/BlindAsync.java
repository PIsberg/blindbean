package com.blindbean.async;

import com.blindbean.context.BlindContext;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.function.Supplier;

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
 * <p>The internal {@link ExecutorService} is lazily initialized on first use (double-checked
 * locking). Sync-only users pay no initialization cost. Call {@link #shutdown()} in tests or
 * application teardown.
 */
public final class BlindAsync {

    private static volatile ExecutorService executor;
    private static volatile Semaphore semaphore;
    private static final Object INIT_LOCK = new Object();

    private BlindAsync() {}

    // ── Lazy initialization ───────────────────────────────────────────────

    private static ExecutorService executor() {
        ExecutorService e = executor; // read volatile once into local
        if (e == null) {
            synchronized (INIT_LOCK) {
                e = executor;
                if (e == null) {
                    semaphore = new Semaphore(Runtime.getRuntime().availableProcessors());
                    e = executor = Executors.newVirtualThreadPerTaskExecutor();
                    Runtime.getRuntime().addShutdownHook(new Thread(BlindAsync::shutdown, "blindbean-async-shutdown"));
                }
            }
        }
        return e; // always return the local — never re-reads the volatile
    }

    private static Semaphore semaphore() {
        executor(); // ensure co-initialized
        return semaphore;
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
        for (;;) {
            ExecutorService exec = executor();
            try {
                return CompletableFuture.runAsync(() -> {
                    Semaphore sem = semaphore(); // capture once — acquire and release must be symmetric
                    sem.acquireUninterruptibly();
                    try {
                        BlindContext.restore(snapshot);
                        task.run();
                    } finally {
                        sem.release();
                    }
                }, exec);
            } catch (java.util.concurrent.RejectedExecutionException ignored) {
                // exec was concurrently shut down; executor() will reinitialize on the next iteration
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
        for (;;) {
            ExecutorService exec = executor();
            try {
                return CompletableFuture.supplyAsync(() -> {
                    Semaphore sem = semaphore(); // capture once — acquire and release must be symmetric
                    sem.acquireUninterruptibly();
                    try {
                        BlindContext.restore(snapshot);
                        return task.get();
                    } finally {
                        sem.release();
                    }
                }, exec);
            } catch (java.util.concurrent.RejectedExecutionException ignored) {
                // exec was concurrently shut down; executor() will reinitialize on the next iteration
            }
        }
    }

    /**
     * Shuts down the internal executor. Safe to call multiple times.
     * Subsequent calls to {@link #runAsync} or {@link #supplyAsync} will reinitialize it.
     */
    public static void shutdown() {
        ExecutorService toClose;
        synchronized (INIT_LOCK) {
            toClose   = executor;
            executor  = null;  // null before close() so concurrent runAsync callers block on INIT_LOCK instead of spinning
            semaphore = null;
        }
        if (toClose != null) {
            toClose.close();
        }
    }
}

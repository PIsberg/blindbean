package se.deversity.blindbean.fhe;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.lang.foreign.MemorySegment;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pins what {@code FheContext.nativeLock} is for: {@code close()} frees the native context and
 * closes its arena, so it must never run while another thread is inside a native call on that
 * context, and a call that starts after it must fail cleanly.
 *
 * <p>The contract under test: every operation racing a {@code close()} either completes with the
 * right answer or throws {@code FheException("FheContext has been closed")}. Nothing else is
 * allowed: not an {@code IllegalStateException} from a closed arena, not a wrong value, and not a
 * crashed JVM (which surefire reports as a forked VM that terminated without saying goodbye).
 *
 * <p>{@code FheAsyncConcurrencyTest.concurrentBfvOperationsAreThreadSafe} passed with the lock
 * removed (#268): SEAL tolerates concurrent encrypt/add/decrypt on distinct ciphertexts, so that
 * test only measured lock waiting. This one goes red without the lock on {@code encryptLong} and
 * {@code decryptLong}; see the PR for #268 for the measured failure.
 *
 * <p>Plain threads rather than {@code @AsyncTest}: each round needs a fresh context, and the
 * library's per-round hooks apply to every {@code @AsyncTest} in a class.
 */
@Tag("native")
class FheContextCloseRaceTest {

    private static final int ROUNDS = 40;
    private static final int WORKERS = 8;

    @Test
    void operationsRacingCloseEitherSucceedOrReportTheContextClosed() throws Exception {
        ConcurrentLinkedQueue<Throwable> unexpected = new ConcurrentLinkedQueue<>();
        int completedOps = 0;
        int closedRefusals = 0;

        for (int round = 0; round < ROUNDS; round++) {
            // 4096 for speed: this tests lifecycle, not parameters, and the race needs many rounds.
            FheContext ctx = FheContext.bfv(4096);
            CountDownLatch start = new CountDownLatch(1);
            int[] completed = new int[WORKERS];
            boolean[] refused = new boolean[WORKERS];
            List<Thread> workers = new java.util.ArrayList<>();

            for (int w = 0; w < WORKERS; w++) {
                int id = w;
                workers.add(Thread.ofPlatform().start(() -> {
                    try {
                        start.await();
                        while (true) {
                            long value = ThreadLocalRandom.current().nextLong(1000);
                            MemorySegment ct = ctx.encryptLong(value);
                            try {
                                assertEquals(value, ctx.decryptLong(ct), "a completed round trip must be exact");
                                completed[id]++;
                            } finally {
                                ctx.freeCiphertext(ct);
                            }
                        }
                    } catch (FheException e) {
                        if (e.getMessage() != null && e.getMessage().contains("has been closed")) {
                            refused[id] = true;
                        } else {
                            unexpected.add(e);
                        }
                    } catch (Throwable t) {
                        unexpected.add(t);
                    }
                }));
            }

            start.countDown();
            // Let the workers get into native calls, then pull the context out from under them.
            LockSupport.parkNanos(TimeUnit.MICROSECONDS.toNanos(ThreadLocalRandom.current().nextInt(200, 3000)));
            try {
                ctx.close();
            } catch (Throwable t) {
                unexpected.add(t);
            }
            for (Thread t : workers) {
                t.join(TimeUnit.SECONDS.toMillis(30));
                assertTrue(!t.isAlive(), "a worker never noticed the context closing");
            }
            for (int w = 0; w < WORKERS; w++) {
                completedOps += completed[w];
                closedRefusals += refused[w] ? 1 : 0;
            }
        }

        assertTrue(unexpected.isEmpty(),
            "an operation racing close() must succeed or throw FheException(closed); got "
            + unexpected.size() + ", first: " + unexpected.peek());
        // Guard against a test that never raced: both outcomes must actually have happened.
        assertTrue(completedOps > 0, "no operation ever completed, so nothing raced close()");
        assertEquals(ROUNDS * WORKERS, closedRefusals,
            "every worker must have been stopped by the closed context, not by something else");
    }
}

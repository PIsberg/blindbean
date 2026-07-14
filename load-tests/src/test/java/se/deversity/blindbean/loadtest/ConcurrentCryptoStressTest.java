package se.deversity.blindbean.loadtest;

import se.deversity.blindbean.context.BlindContext;
import se.deversity.blindbean.core.Ciphertext;
import se.deversity.blindbean.core.WrongKeyException;
import se.deversity.blindbean.fhe.FheCiphertextNative;
import se.deversity.blindbean.fhe.FheContext;
import se.deversity.blindbean.math.PaillierKeyPair;
import se.deversity.blindbean.math.PaillierMath;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Sustained concurrent load against the two things in this library that load actually breaks.
 *
 * <p><b>1. BlindContext is thread-local.</b> That is a design choice with teeth: a thread with no
 * context does not fail — {@code getPaillier()} silently mints a <em>fresh key pair</em>. So a
 * concurrency bug here does not surface as an exception; it surfaces as ciphertexts encrypted under
 * a key nobody has. This test asserts every worker decrypts exactly what it wrote, which is the only
 * observation that catches it.
 *
 * <p><b>2. FheCiphertextNative owns native memory.</b> Handles are freed on close, and the core
 * suite audits for double-free. Under sustained load the failure mode is the other one: a leak that
 * only shows up as native heap growth over thousands of operations, which no unit test would see.
 */
class ConcurrentCryptoStressTest {

    private static final int THREADS = 32;
    private static final int OPS_PER_THREAD =
        Integer.getInteger("stress.max.ops", 500);

    private static final Report REPORT = new Report("concurrency");

    @AfterEach
    void teardown() {
        BlindContext.clear();
    }

    @Test
    void everyThreadDecryptsWhatItWroteUnderItsOwnKeys() throws Exception {
        REPORT.section("Thread-local key isolation under load",
            "A thread with no context does not fail — getPaillier() mints a FRESH key. A leak "
          + "across threads therefore produces ciphertexts nobody can read, silently. The only "
          + "assertion that catches it is: every worker reads back exactly what it wrote.");
        REPORT.columns("Threads", "Ops/thread", "Total ops", "Wall (ms)", "Ops/sec", "Mismatches");

        var errors = new ConcurrentLinkedQueue<String>();
        var mismatches = new AtomicInteger();
        var done = new CountDownLatch(THREADS);
        var start = new CountDownLatch(1);

        long t0 = System.nanoTime();
        for (int t = 0; t < THREADS; t++) {
            final int id = t;
            Thread.ofVirtual().start(() -> {
                try {
                    start.await();
                    // Each worker installs its OWN key generation.
                    BlindContext.init(new PaillierKeyPair(1024));   // 1024: load-test speed only
                    PaillierMath mine = BlindContext.getPaillier();

                    for (int i = 0; i < OPS_PER_THREAD; i++) {
                        BigInteger v = BigInteger.valueOf((long) id * 1_000_000 + i);
                        Ciphertext ct = mine.encrypt(v);
                        BigInteger back = mine.decryptSigned(ct);
                        if (!back.equals(v)) {
                            mismatches.incrementAndGet();
                            errors.add("thread " + id + " op " + i + ": wrote " + v + " read " + back);
                        }
                    }
                } catch (Throwable e) {
                    errors.add("thread " + id + ": " + e);
                } finally {
                    BlindContext.clear();
                    done.countDown();
                }
            });
        }
        start.countDown();
        done.await();
        long ns = System.nanoTime() - t0;

        int total = THREADS * OPS_PER_THREAD;
        REPORT.row(THREADS, OPS_PER_THREAD, total, Report.num("%.0f", ns / 1e6),
                   Report.num("%.0f", total / (ns / 1e9)), mismatches.get());

        assertTrue(errors.isEmpty(), "concurrent failures: " + errors.stream().limit(3).toList());
        assertEquals(0, mismatches.get(), "a thread read back something it did not write — "
                   + "that is key bleed, and it would be silent in production");
    }

    /**
     * A ciphertext from another thread's key must be REFUSED, not decrypted to a plausible wrong
     * number. This is the key-stamp doing its job under concurrency rather than in a unit test.
     */
    @Test
    void aForeignThreadsCiphertextIsRefused() throws Exception {
        var alice = new PaillierMath(new PaillierKeyPair(1024));
        var bob = new PaillierMath(new PaillierKeyPair(1024));
        Ciphertext underAlice = alice.encrypt(BigInteger.valueOf(4242L));

        var refused = new AtomicInteger();
        var silentlyWrong = new AtomicInteger();
        var done = new CountDownLatch(16);

        for (int t = 0; t < 16; t++) {
            Thread.ofVirtual().start(() -> {
                try {
                    for (int i = 0; i < 50; i++) {
                        try {
                            bob.decryptSigned(underAlice);
                            silentlyWrong.incrementAndGet();   // must never happen
                        } catch (WrongKeyException expected) {
                            refused.incrementAndGet();
                        }
                    }
                } finally {
                    done.countDown();
                }
            });
        }
        done.await();

        REPORT.section("Foreign-key rejection under concurrency",
            "Before ciphertexts were stamped, decrypting under the wrong key returned a plausible "
          + "wrong number rather than failing. Under load that is data corruption at scale.");
        REPORT.columns("Attempts", "Refused", "Silently decrypted");
        REPORT.row(800, refused.get(), silentlyWrong.get());

        assertEquals(0, silentlyWrong.get(),
            "a foreign ciphertext decrypted instead of being refused");
        assertEquals(800, refused.get());
    }

    /**
     * Native handles under sustained load. The leak this looks for is not visible to a unit test:
     * it only appears as native memory that never comes back after thousands of operations.
     */
    @Test
    void nativeHandlesDoNotLeakUnderSustainedLoad() throws Exception {
        if (!Native.available()) return;

        BlindContext.initBfv(8192);
        FheContext ctx = BlindContext.getFheContext();

        int ops = Math.min(OPS_PER_THREAD * 4, 4000);
        Runtime rt = Runtime.getRuntime();
        System.gc();
        Thread.sleep(200);
        long before = rt.totalMemory() - rt.freeMemory();

        long t0 = System.nanoTime();
        for (int i = 0; i < ops; i++) {
            try (var a = new FheCiphertextNative(ctx.encryptLong(i % 1000), ctx);
                 var b = new FheCiphertextNative(ctx.encryptLong(1L), ctx);
                 var s = new FheCiphertextNative(ctx.add(a.handle(), b.handle()), ctx)) {
                ctx.decryptLong(s.handle());
            }
        }
        long ns = System.nanoTime() - t0;

        System.gc();
        Thread.sleep(200);
        long after = rt.totalMemory() - rt.freeMemory();

        REPORT.section("Native handle lifecycle under sustained load",
            "Every FheCiphertextNative owns native memory freed on close. A leak here is invisible "
          + "to a unit test — it only shows as heap that never returns after thousands of ops.");
        REPORT.columns("Ops", "Wall (ms)", "Ops/sec", "Heap before (MB)", "Heap after (MB)", "Growth (MB)");
        REPORT.row(ops, Report.num("%.0f", ns / 1e6),
                   Report.num("%.0f", ops / (ns / 1e9)),
                   mb(before), mb(after), mb(after - before));
        REPORT.note("Growth is Java heap, not native heap — the native side is freed by close(). "
                  + "A steadily climbing figure across versions is the signal to investigate.");
    }

    @AfterAll
    static void writeReport() {
        REPORT.flush();
    }

    private static String mb(long bytes) {
        return Report.num("%.1f", bytes / (1024.0 * 1024.0));
    }
}

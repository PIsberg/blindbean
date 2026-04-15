package com.blindbean.async;

import com.blindbean.context.BlindContext;
import com.blindbean.math.PaillierMath;
import com.blindbean.core.Ciphertext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class BlindAsyncTest {

    @BeforeEach
    void setup() {
        BlindContext.init();
        BlindAsync.shutdown(); // ensure clean executor for each test
    }

    @AfterEach
    void teardown() {
        BlindAsync.shutdown();
        BlindContext.clear();
    }

    @Test
    void runAsyncExecutesOnVirtualThread() throws Exception {
        AtomicReference<Boolean> isVirtual = new AtomicReference<>();

        BlindAsync.runAsync(() -> isVirtual.set(Thread.currentThread().isVirtual())).get();

        assertTrue(isVirtual.get(), "Expected virtual thread");
    }

    @Test
    void supplyAsyncReturnsValue() throws Exception {
        BigInteger value = BigInteger.valueOf(42);

        BigInteger result = BlindAsync.<BigInteger>supplyAsync(() -> value).get();

        assertEquals(value, result);
    }

    @Test
    void blindContextSnapshotPropagatedToVirtualThread() throws Exception {
        // Capture current thread's PaillierMath instance
        PaillierMath callerPaillier = BlindContext.getPaillier();

        AtomicReference<PaillierMath> asyncPaillier = new AtomicReference<>();
        BlindAsync.runAsync(() -> asyncPaillier.set(BlindContext.getPaillier())).get();

        assertSame(callerPaillier, asyncPaillier.get(),
                "Virtual thread should use the same PaillierMath as the caller");
    }

    @Test
    void semaphoreLimitsConcurrentTasks() throws Exception {
        int cores = Runtime.getRuntime().availableProcessors();
        int tasks = cores * 4;

        AtomicInteger concurrentPeak = new AtomicInteger(0);
        AtomicInteger active         = new AtomicInteger(0);
        // Each task holds its permit until releaseAll fires, letting us count simultaneous holders
        CountDownLatch allSlotsHeld = new CountDownLatch(cores);
        CountDownLatch releaseAll   = new CountDownLatch(1);

        List<CompletableFuture<Void>> futures = new ArrayList<>();
        for (int i = 0; i < tasks; i++) {
            futures.add(BlindAsync.runAsync(() -> {
                int current = active.incrementAndGet();
                concurrentPeak.accumulateAndGet(current, Math::max);
                allSlotsHeld.countDown();
                try { releaseAll.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
                active.decrementAndGet();
            }));
        }

        // Wait until all semaphore permits are held (exactly `cores` tasks inside), then release
        assertTrue(allSlotsHeld.await(5, TimeUnit.SECONDS), "Tasks did not fill semaphore slots in time");
        releaseAll.countDown();
        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).get();

        assertTrue(concurrentPeak.get() <= cores,
                "Peak concurrency " + concurrentPeak.get() + " exceeded core count " + cores);
    }

    @Test
    void encryptDecryptRoundTripViaAsync() throws Exception {
        // Ensure the full encrypt→decrypt cycle works end-to-end on a virtual thread
        BigInteger original = BigInteger.valueOf(999);
        AtomicReference<BigInteger> decrypted = new AtomicReference<>();

        BlindAsync.runAsync(() -> {
            Ciphertext ct = BlindContext.getPaillier().encrypt(original);
            BigInteger plain = BlindContext.getPaillier().decrypt(ct);
            decrypted.set(plain);
        }).get();

        assertEquals(original, decrypted.get());
    }
}

package se.deversity.blindbean.loadtest;

import se.deversity.blindbean.context.BlindContext;
import se.deversity.blindbean.core.Ciphertext;
import se.deversity.blindbean.fhe.FheCiphertextNative;
import se.deversity.blindbean.fhe.FheContext;
import se.deversity.blindbean.math.PaillierKeyPair;
import se.deversity.blindbean.math.PaillierMath;

import com.sun.management.OperatingSystemMXBean;
import com.sun.management.ThreadMXBean;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.lang.management.ManagementFactory;
import java.lang.management.MemoryPoolMXBean;
import java.lang.management.MemoryType;
import java.math.BigInteger;
import java.util.function.IntConsumer;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * What a crypto workload actually costs the machine — CPU and memory — not just how fast it runs.
 *
 * <p>The rest of this harness answers "how many microseconds is an add" ({@code CryptoHotPathBenchmark})
 * and "does anything leak" ({@code ConcurrentCryptoStressTest}). Neither answers "how much CPU and how
 * much heap does a representative round-trip burn", which is the number you watch to catch a feature
 * that quietly doubles the work or the allocation. That is what this test measures and records to
 * {@code target/resource-usage.txt}, so a regression across versions is a diff.
 *
 * <p><b>Why these metrics and not wall-clock.</b> Wall time on a shared CI runner is noise. Two of the
 * figures here are not:
 * <ul>
 *   <li><b>Process CPU time</b> ({@code getProcessCpuTime}) counts CPU actually consumed across all
 *       threads. It survives a slow, contended runner — a run that takes twice the wall clock because
 *       the box was busy still reports the same CPU-nanoseconds of real work. CPU-per-op and the
 *       cores-utilised ratio (CPU time / wall time) are the load figures that mean something.</li>
 *   <li><b>Bytes allocated</b> ({@code getTotalThreadAllocatedBytes}) is deterministic — it does not
 *       depend on the runner at all. Allocation-per-op climbing is the earliest, cleanest signal that
 *       a change started churning garbage on the hot path.</li>
 * </ul>
 * Peak heap is reported too (it depends on GC timing, so it is watched, not asserted tightly).
 *
 * <p>The assertions are deliberately generous ceilings — properties, not magnitudes — so this is a
 * gate that catches a blow-up (a leak, an accidental O(n) allocation) without going red on runner
 * jitter. The trend lives in the committed {@code results/} diff, matching the rest of the harness.
 */
class ResourceUsageTest {

    /** Scales with the same knob the CI gate turns down (default 500; the gate runs 50). */
    private static final int OPS = Integer.getInteger("stress.max.ops", 500);

    private static final Report REPORT = new Report("resource-usage");

    private static final OperatingSystemMXBean OS =
        (OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();
    private static final ThreadMXBean THREADS =
        (ThreadMXBean) ManagementFactory.getThreadMXBean();

    /** One captured measurement of a workload. */
    private record Usage(long ops, long wallNs, long cpuNs, long allocBytes, long peakHeap) {
        double cpuUsPerOp()  { return cpuNs   >= 0 ? (cpuNs / 1e3)  / ops : Double.NaN; }
        double allocKbPerOp(){ return allocBytes >= 0 ? (allocBytes / 1024.0) / ops : Double.NaN; }
        /** Wall-clock parallelism: CPU-seconds burned per wall-second. ~1.0 = one core saturated. */
        double coresUsed()   { return cpuNs >= 0 && wallNs > 0 ? (double) cpuNs / wallNs : Double.NaN; }
        double peakHeapMb()  { return peakHeap / (1024.0 * 1024.0); }
    }

    @AfterEach
    void teardown() {
        BlindContext.clear();
    }

    @Test
    void paillierRoundTripCpuAndMemory() {
        // 1024-bit keys: load-test speed only, same as the concurrency harness.
        PaillierMath math = new PaillierMath(new PaillierKeyPair(1024));
        Ciphertext one = math.encrypt(BigInteger.ONE);

        Usage u = measure(OPS, i -> {
            Ciphertext ct = math.encrypt(BigInteger.valueOf(i));
            Ciphertext sum = math.add(ct, one);
            math.decryptSigned(sum);
        });

        REPORT.section("Paillier round-trip resource cost (encrypt + add + decrypt)",
            "CPU and heap a representative Paillier round-trip actually burns. CPU-per-op and "
          + "bytes-per-op are runner-independent; a jump in either flags a feature that quietly "
          + "doubled the work or the garbage, which a pass/fail unit test never would.");
        reportRow("Paillier-1024 round-trip", u);

        assertSaneUsage("Paillier round-trip", u);
    }

    @Test
    void bfvRoundTripCpuAndMemory() {
        if (!Native.available()) return;

        BlindContext.initBfv(8192);
        FheContext ctx = BlindContext.getFheContext();

        // Fewer native round-trips: each is far heavier than a Paillier op.
        int ops = Math.max(20, OPS / 4);
        Usage u = measure(ops, i -> {
            try (var a = new FheCiphertextNative(ctx.encryptLong(i % 1000), ctx);
                 var b = new FheCiphertextNative(ctx.encryptLong(1L), ctx);
                 var s = new FheCiphertextNative(ctx.add(a.handle(), b.handle()), ctx)) {
                ctx.decryptLong(s.handle());
            }
        });

        REPORT.section("BFV round-trip resource cost (encrypt + add + decrypt)",
            "Same measurement across the native SEAL bridge. Java-heap allocation here is the "
          + "marshalling cost of crossing the FFM boundary — the SEAL ciphertext itself lives on "
          + "the native heap, freed by close(), and is not counted in these bytes.");
        reportRow("BFV-8192 round-trip", u);

        assertSaneUsage("BFV round-trip", u);
    }

    // ── measurement plumbing ──────────────────────────────────────────────────

    private static Usage measure(int ops, IntConsumer work) {
        // Warm the JIT and the key/native caches so the measured window is steady state, not startup.
        for (int i = 0; i < Math.min(ops, 100); i++) work.accept(i);

        resetPeakHeap();
        System.gc();
        sleep(150);

        long alloc0 = totalAllocatedBytes();
        long cpu0 = OS.getProcessCpuTime();      // ns of CPU across all threads (-1 if unsupported)
        long wall0 = System.nanoTime();

        for (int i = 0; i < ops; i++) work.accept(i);

        long wallNs = System.nanoTime() - wall0;
        long cpuNs = cpu0 >= 0 ? OS.getProcessCpuTime() - cpu0 : -1;
        long allocBytes = alloc0 >= 0 ? totalAllocatedBytes() - alloc0 : -1;
        long peak = peakHeapBytes();
        return new Usage(ops, wallNs, cpuNs, allocBytes, peak);
    }

    private static void reportRow(String label, Usage u) {
        REPORT.columns("Workload", "Ops", "CPU us/op", "Cores used", "Alloc KB/op", "Peak heap (MB)");
        REPORT.row(label, u.ops(),
                   fmt(u.cpuUsPerOp()), fmt(u.coresUsed()), fmt(u.allocKbPerOp()),
                   Report.num("%.1f", u.peakHeapMb()));
        REPORT.note("CPU us/op and Alloc KB/op are the trend numbers to watch — both are "
                  + "runner-independent. A steady climb across versions means a feature got more "
                  + "expensive; copy this file into results/<version>/ at release time so it diffs.");
    }

    /**
     * Generous ceilings, not tight magnitudes: this catches a blow-up (a leak, an accidental
     * per-op allocation of megabytes) while staying green on ordinary runner jitter. The trend
     * itself is read from the committed results diff, not asserted here.
     */
    private static void assertSaneUsage(String what, Usage u) {
        assertTrue(u.wallNs() > 0, what + ": wall time not measured");
        if (u.cpuNs() >= 0) {
            assertTrue(u.cpuNs() > 0, what + ": process CPU time read as zero — measurement broken");
            // A single crypto round-trip cannot legitimately parallelise onto many cores; if the
            // ratio blew past the box's core count, the measurement (or a runaway thread) is wrong.
            assertTrue(u.coresUsed() <= OS.getAvailableProcessors() + 1.0,
                what + ": CPU/wall ratio implausibly high (" + fmt(u.coresUsed()) + ")");
        }
        if (u.allocBytes() >= 0) {
            // 8 MB/op is orders of magnitude above any real round-trip here; only a runaway hits it.
            assertTrue(u.allocKbPerOp() < 8 * 1024,
                what + ": allocation per op blew past ceiling (" + fmt(u.allocKbPerOp()) + " KB/op)");
        }
    }

    private static long totalAllocatedBytes() {
        try {
            if (THREADS.isThreadAllocatedMemorySupported() && THREADS.isThreadAllocatedMemoryEnabled()) {
                return THREADS.getTotalThreadAllocatedBytes();
            }
        } catch (UnsupportedOperationException ignored) {
            // fall through
        }
        return -1;
    }

    private static void resetPeakHeap() {
        for (MemoryPoolMXBean p : ManagementFactory.getMemoryPoolMXBeans()) {
            if (p.getType() == MemoryType.HEAP) p.resetPeakUsage();
        }
    }

    private static long peakHeapBytes() {
        long peak = 0;
        for (MemoryPoolMXBean p : ManagementFactory.getMemoryPoolMXBeans()) {
            if (p.getType() == MemoryType.HEAP) peak += Math.max(0, p.getPeakUsage().getUsed());
        }
        return peak;
    }

    private static String fmt(double d) {
        return Double.isNaN(d) ? "n/a" : Report.num("%.2f", d);
    }

    private static void sleep(long ms) {
        try { Thread.sleep(ms); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    @AfterAll
    static void writeReport() {
        REPORT.flush();
    }
}

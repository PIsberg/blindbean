package se.deversity.blindbean.loadtest;

import se.deversity.blindbean.context.BlindContext;
import se.deversity.blindbean.core.Ciphertext;
import se.deversity.blindbean.fhe.FheCiphertextNative;
import se.deversity.blindbean.fhe.FheContext;
import se.deversity.blindbean.math.PaillierKeyPair;
import se.deversity.blindbean.math.PaillierMath;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertTrue;
import java.util.ArrayList;
import java.util.List;

/**
 * The metrics that are specific to homomorphic encryption — the ones a user cannot discover from a
 * throughput number, and which decide whether their design is viable at all.
 *
 * <p>Reported here, none of which a generic load test would surface:
 *
 * <ul>
 *   <li><b>Ciphertext expansion</b> — bytes out per byte in. This is <em>the</em> headline cost of
 *       HE and it decides your storage bill and your column types. A `long` under BFV is not 8
 *       bytes on disk.</li>
 *   <li><b>Noise budget → multiplicative depth</b> — every homomorphic operation consumes noise
 *       budget; at zero, the ciphertext stops decrypting to anything meaningful. The number that
 *       matters is therefore not "how fast is a multiply" but <b>how many multiplies can I chain
 *       before my data silently becomes garbage</b>. Nothing else in this repo measures it, and
 *       `FheContext.noiseBudget()` existed unused.</li>
 *   <li><b>CKKS precision decay</b> — CKKS is approximate, so the question is how many correct
 *       decimal digits survive N operations. "Approximate" is not a number; this is.</li>
 *   <li><b>Batching amortisation</b> — cost per slot for a vector op vs a scalar op. This is the
 *       entire reason to use BFV/CKKS batching, and it is now measurable for CKKS too.</li>
 *   <li><b>Keygen cost by modulus size</b> — Paillier keygen is the slowest thing in the library
 *       and grows sharply. The default moved 1024 → 2048 for security; this prices that.</li>
 * </ul>
 *
 * <p>Results print to stdout and land in {@code target/}. Check a copy into
 * {@code results/<version>/} when a release is cut, so regressions are visible across versions.
 */
class CryptoMetricsTest {

    private static final Report REPORT = new Report("crypto-metrics");

    /**
     * Caps the two loops that dominate the runtime (the scalar batching baseline and the CKKS
     * add chain). CI passes a small value so this doubles as a fast regression gate; a full local
     * run leaves it at the default and produces the numbers that go in results/.
     */
    private static final int MAX_OPS = Integer.getInteger("stress.max.ops", 4096);

    @AfterEach
    void teardown() {
        BlindContext.clear();
    }

    // ── 1. Ciphertext expansion ──────────────────────────────────────────────

    @Test
    void ciphertextExpansion() {
        REPORT.section("Ciphertext expansion — bytes of ciphertext per byte of plaintext",
            "The storage cost of HE. A `long` is 8 bytes in the clear; measure what it becomes.");
        REPORT.columns("Scheme", "Plaintext", "PT bytes", "CT bytes", "Expansion");

        // Paillier: a ciphertext is an element of Z_{n^2}, so ~2x the modulus regardless of the value.
        for (int bits : new int[] { 1024, 2048, 3072 }) {
            PaillierMath m = new PaillierMath(new PaillierKeyPair(bits));
            Ciphertext ct = m.encrypt(BigInteger.valueOf(42L));
            REPORT.row("PAILLIER-" + bits, "long 42", 8, ct.sizeInBytes(),
                       ratio(ct.sizeInBytes(), 8));
        }

        if (!Native.available()) {
            REPORT.note("BFV/CKKS skipped — native library not present.");
            return;
        }

        // BFV/CKKS: the ciphertext is a polynomial pair. Its size is set by the PARAMETERS, not by
        // the value — so encrypting one long and encrypting 8,192 of them cost the same bytes.
        // That is the whole economic argument for batching.
        BlindContext.initBfv(8192);
        FheContext bfv = BlindContext.getFheContext();
        try (var one = new FheCiphertextNative(bfv.encryptLong(42L), bfv)) {
            int n = one.toBlindCiphertext().sizeInBytes();
            REPORT.row("BFV-8192", "long 42 (1 slot used)", 8, n, ratio(n, 8));
        }
        long[] full = new long[8192];
        double bfvBatchedExpansion;
        try (var vec = new FheCiphertextNative(bfv.encryptLongArray(full), bfv)) {
            int n = vec.toBlindCiphertext().sizeInBytes();
            int pt = 8192 * 8;
            bfvBatchedExpansion = n / (double) pt;
            REPORT.row("BFV-8192", "long[8192] (all slots)", pt, n, ratio(n, pt));
        }
        BlindContext.clear();

        BlindContext.initCkks(8192, Math.pow(2, 40));
        FheContext ckks = BlindContext.getFheContext();
        try (var one = new FheCiphertextNative(ckks.encryptDouble(3.14), ckks)) {
            int n = one.toBlindCiphertext().sizeInBytes();
            REPORT.row("CKKS-8192", "double 3.14 (1 slot)", 8, n, ratio(n, 8));
        }
        try (var vec = new FheCiphertextNative(ckks.encryptDoubleArray(new double[4096]), ckks)) {
            int n = vec.toBlindCiphertext().sizeInBytes();
            int pt = 4096 * 8;
            REPORT.row("CKKS-8192", "double[4096] (all slots)", pt, n, ratio(n, pt));
        }
        REPORT.note("Ciphertext size is fixed by the parameters, not the payload: one value costs "
                  + "the same bytes as a full slot vector. Batching is not an optimisation here, "
                  + "it is how you stop paying for empty slots.");

        // Regression gate: a filled BFV vector must stay in single digits of expansion. If this
        // ever blows up, the batch path has silently stopped filling slots.
        assertTrue(bfvBatchedExpansion < 20,
            "BFV batched expansion regressed to " + bfvBatchedExpansion + "x (was ~7x)");
    }

    // ── 2. Noise budget → multiplicative depth ───────────────────────────────

    @Test
    void noiseBudgetAndMultiplicativeDepth() {
        if (!Native.available()) return;

        REPORT.section("Noise budget → multiplicative depth (BFV)",
            "Every operation spends noise budget. At zero the ciphertext is garbage. SEAL returns a "
          + "plausible wrong number rather than failing, so BlindBean refuses to decrypt it (the "
          + "noise guard). The useful number is not the speed of a multiply but how many you can "
          + "chain before you hit the wall.");
        REPORT.columns("Depth", "Op", "Noise budget (bits)", "Decrypts correctly?");

        BlindContext.initBfv(8192);
        FheContext ctx = BlindContext.getFheContext();

        // x = 2, then repeatedly square-ish: multiply by a fresh encryption of 2.
        long expected = 2L;
        var acc = new FheCiphertextNative(ctx.encryptLong(2L), ctx);
        REPORT.row(0, "encrypt(2)", ctx.noiseBudget(acc.handle()),
                   ctx.decryptLong(acc.handle()) == expected);

        int depth = 0;
        int lastGoodDepth = 0;
        while (depth < 12) {
            depth++;
            // Values must stay inside the ~20-bit slot: 2^12 = 4096 is safely under maxSlotValue().
            try (var two = new FheCiphertextNative(ctx.encryptLong(2L), ctx)) {
                var next = new FheCiphertextNative(ctx.multiply(acc.handle(), two.handle()), ctx);
                acc.close();
                acc = next;
            }
            expected *= 2L;

            int budget = ctx.noiseBudget(acc.handle());

            // Past the cliff the library now REFUSES to decrypt (FheContext's noise guard) rather
            // than handing back the plausible wrong number it used to. This sweep is the one place
            // that wants to observe the failure, so it records the refusal instead of propagating it.
            boolean ok;
            String verdict;
            try {
                long got = ctx.decryptLong(acc.handle());
                ok = got == expected;
                verdict = ok ? "yes" : "NO — returned " + got;
            } catch (se.deversity.blindbean.fhe.FheException refused) {
                ok = false;
                verdict = "REFUSED (noise guard)";
            }
            REPORT.row(depth, "× encrypt(2)", budget, verdict);
            if (ok) lastGoodDepth = depth;
            if (budget <= 0 || !ok) break;
        }
        acc.close();

        REPORT.note("Usable multiplicative depth at these parameters: " + lastGoodDepth
                  + ". Beyond it the ciphertext is garbage. Before the noise guard it decrypted to a "
                  + "plausible wrong number (49,663 where 64 was expected) with no exception and no "
                  + "warning; it is now refused. An application chaining multiplies should still "
                  + "watch noiseBudget() — the guard tells you that you ran out, not that you are "
                  + "about to.");

        // Regression gate. Depth is a property of the PARAMETERS, so a SEAL upgrade or a parameter
        // tweak that quietly costs a multiply would otherwise ship unnoticed — and every user who
        // relied on four would start getting silent garbage.
        assertTrue(lastGoodDepth >= 4,
            "multiplicative depth regressed to " + lastGoodDepth + " (expected >= 4)");
    }

    // ── 3. CKKS precision decay ──────────────────────────────────────────────

    @Test
    void ckksPrecisionDecay() {
        if (!Native.available()) return;

        REPORT.section("CKKS precision decay",
            "CKKS is approximate. 'Approximate' is not a number — this is: how many correct decimal "
          + "digits survive N chained additions.");
        REPORT.columns("Ops", "Expected", "Got", "Abs error", "Correct digits");

        BlindContext.initCkks(8192, Math.pow(2, 40));
        FheContext ctx = BlindContext.getFheContext();

        double step = 0.1;
        double expected = step;
        var acc = new FheCiphertextNative(ctx.encryptDouble(step), ctx);

        for (int ops : new int[] { 1, 10, 100, 1000 }) {
            if (ops > MAX_OPS) break;
            while (countedOps < ops) {
                try (var s = new FheCiphertextNative(ctx.encryptDouble(step), ctx)) {
                    var next = new FheCiphertextNative(ctx.add(acc.handle(), s.handle()), ctx);
                    acc.close();
                    acc = next;
                }
                expected += step;
                countedOps++;
            }
            double got = ctx.decryptDouble(acc.handle());
            double err = Math.abs(got - expected);
            REPORT.row(ops, fmt(expected), fmt(got), Report.num("%.3e", err), digits(err, expected));
        }
        acc.close();
        countedOps = 0;
        REPORT.note("Additions are cheap in noise; the drift above is the encoding approximation, "
                  + "not noise exhaustion. Never use CKKS for money — BigDecimal on Paillier is exact.");
    }

    private int countedOps = 0;

    // ── 4. Batching amortisation ─────────────────────────────────────────────

    @Test
    void batchingAmortisation() {
        if (!Native.available()) return;

        REPORT.section("Batching amortisation — cost per value",
            "One homomorphic op applies to every slot. This prices the SIMD win: the whole reason "
          + "to reach for BFV/CKKS over a scalar scheme.");
        REPORT.columns("Scheme", "Mode", "Values", "Total (ms)", "Per value (us)");

        BlindContext.initBfv(8192);
        FheContext bfv = BlindContext.getFheContext();
        int n = Math.min(4096, MAX_OPS);

        long t0 = System.nanoTime();
        for (int i = 0; i < n; i++) {
            try (var a = new FheCiphertextNative(bfv.encryptLong(i % 1000), bfv);
                 var b = new FheCiphertextNative(bfv.encryptLong(1L), bfv);
                 var s = new FheCiphertextNative(bfv.add(a.handle(), b.handle()), bfv)) {
                // one value per ciphertext — 4096 separate ops
            }
        }
        long scalarNs = System.nanoTime() - t0;
        REPORT.row("BFV", "scalar (1 value/ct)", n, ms(scalarNs), perValueUs(scalarNs, n));

        long[] vec = new long[n];
        for (int i = 0; i < n; i++) vec[i] = i % 1000;
        t0 = System.nanoTime();
        try (var a = new FheCiphertextNative(bfv.encryptLongArray(vec), bfv);
             var b = new FheCiphertextNative(bfv.encryptLongArray(ones(n)), bfv);
             var s = new FheCiphertextNative(bfv.add(a.handle(), b.handle()), bfv)) {
            bfv.decryptLongArray(s.handle());
        }
        long batchNs = System.nanoTime() - t0;
        REPORT.row("BFV", "batched (n values/ct)", n, ms(batchNs), perValueUs(batchNs, n));
        BlindContext.clear();

        BlindContext.initCkks(8192, Math.pow(2, 40));
        FheContext ckks = BlindContext.getFheContext();
        int m = Math.min(2048, MAX_OPS);

        t0 = System.nanoTime();
        for (int i = 0; i < m; i++) {
            try (var a = new FheCiphertextNative(ckks.encryptDouble(i * 0.5), ckks);
                 var b = new FheCiphertextNative(ckks.encryptDouble(1.0), ckks);
                 var s = new FheCiphertextNative(ckks.add(a.handle(), b.handle()), ckks)) {
            }
        }
        long ckksScalarNs = System.nanoTime() - t0;
        REPORT.row("CKKS", "scalar (1 value/ct)", m, ms(ckksScalarNs), perValueUs(ckksScalarNs, m));

        double[] dv = new double[m];
        for (int i = 0; i < m; i++) dv[i] = i * 0.5;
        t0 = System.nanoTime();
        try (var a = new FheCiphertextNative(ckks.encryptDoubleArray(dv), ckks);
             var b = new FheCiphertextNative(ckks.encryptDoubleArray(dv), ckks);
             var s = new FheCiphertextNative(ckks.add(a.handle(), b.handle()), ckks)) {
            ckks.decryptDoubleArray(s.handle());
        }
        long ckksBatchNs = System.nanoTime() - t0;
        REPORT.row("CKKS", "batched (n values/ct)", m, ms(ckksBatchNs), perValueUs(ckksBatchNs, m));

        REPORT.note("Batching speedup — BFV "
                  + Report.num("%.0fx", (double) scalarNs / batchNs)
                  + ", CKKS " + Report.num("%.0fx", (double) ckksScalarNs / ckksBatchNs)
                  + ". The CKKS path did not exist before the double[] bridge: every CKKS "
                  + "ciphertext used to waste all but one of its 4,096 slots. If you are encrypting "
                  + "values one at a time under BFV or CKKS, you are paying three to four orders of "
                  + "magnitude more than you need to.");

        // Regression gate: losing the batch path is the failure this whole harness exists to catch.
        // Deliberately loose (100x, not 3,400x) — a shared CI runner is noisy, and a gate that
        // flaps is a gate people switch off.
        //
        // Only meaningful at a realistic batch size. A batched ciphertext costs the same fixed
        // ~432 KB whether it carries 50 values or 4,096, so under a small -Dstress.max.ops the
        // per-value advantage legitimately collapses (measured 40x at n=50). Asserting there would
        // make the gate permanently red for the exact reason the chart above explains.
        if (n >= 1000) {
            assertTrue(scalarNs / (double) batchNs > 100,
                "BFV batching speedup collapsed to " + (scalarNs / batchNs) + "x at n=" + n);
        }
        if (m >= 1000) {
            assertTrue(ckksScalarNs / (double) ckksBatchNs > 100,
                "CKKS batching speedup collapsed to " + (ckksScalarNs / ckksBatchNs) + "x at n=" + m);
        }
    }

    // ── 5. Keygen cost by modulus size ───────────────────────────────────────

    @Test
    void paillierKeygenCost() {
        REPORT.section("Paillier keygen cost by modulus size",
            "Keygen is the slowest thing in the library and grows sharply. The default moved "
          + "1024 → 2048 because 1024 is ~80-bit security; this prices that decision.");
        REPORT.columns("Modulus bits", "Security", "Keygen (ms, median of 3)");

        for (int bits : new int[] { 1024, 2048, 3072 }) {
            long[] runs = new long[3];
            for (int i = 0; i < 3; i++) {
                long t = System.nanoTime();
                new PaillierKeyPair(bits);
                runs[i] = System.nanoTime() - t;
            }
            java.util.Arrays.sort(runs);
            String sec = switch (bits) {
                case 1024 -> "~80-bit (disallowed since 2013)";
                case 2048 -> "~112-bit (current default)";
                default   -> "~128-bit";
            };
            REPORT.row(bits, sec, ms(runs[1]));
        }
        REPORT.note("Keygen is a per-application cost, not per-request — export the bundle and "
                  + "reload it. If it is on your hot path, that is the bug.");
    }

    /** JUnit does not promise an order, so the report is written once every section has run. */
    @AfterAll
    static void writeReport() {
        REPORT.flush();
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private static long[] ones(int n) {
        long[] a = new long[n];
        java.util.Arrays.fill(a, 1L);
        return a;
    }
    private static String ratio(int ct, int pt) { return Report.num("%.0fx", (double) ct / pt); }
    private static String ms(long ns)           { return Report.num("%.1f", ns / 1e6); }
    private static String perValueUs(long ns, int n) { return Report.num("%.1f", ns / 1e3 / n); }
    private static String fmt(double d)         { return Report.num("%.6f", d); }
    private static String digits(double err, double expected) {
        if (err == 0) return "exact";
        return String.valueOf(Math.max(0, (int) Math.floor(-Math.log10(err / Math.abs(expected)))));
    }
}

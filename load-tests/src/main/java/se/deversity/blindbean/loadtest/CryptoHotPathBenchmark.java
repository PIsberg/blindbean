package se.deversity.blindbean.loadtest;

import se.deversity.blindbean.context.BlindContext;
import se.deversity.blindbean.core.Ciphertext;
import se.deversity.blindbean.fhe.FheCiphertextNative;
import se.deversity.blindbean.fhe.FheContext;
import se.deversity.blindbean.math.PaillierKeyPair;
import se.deversity.blindbean.math.PaillierMath;

import org.openjdk.jmh.annotations.*;

import java.math.BigInteger;
import java.util.concurrent.TimeUnit;

/**
 * Per-operation cost of the primitives, across all three schemes.
 *
 * <p>The sweeps in the JUnit tests answer "does it hold up under load"; this answers "what does one
 * operation actually cost", which is what you need to size a request budget. Run:
 *
 * <pre>
 *   mvn package -DskipTests
 *   java --enable-preview --add-modules jdk.incubator.vector --enable-native-access=ALL-UNNAMED \
 *        -Dblindbean.native.path=../build-native/Release \
 *        -jar target/benchmarks.jar -wi 3 -i 5 -f 1 -tu us -bm avgt -prof gc \
 *        -rf json -rff results/0.1.0/jmh.json
 * </pre>
 *
 * <p>Paillier decrypt is deliberately included: it is a modPow over n², i.e. the most expensive
 * thing on the read path, and the one most likely to be mistaken for cheap.
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@State(Scope.Benchmark)
@Fork(1)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
public class CryptoHotPathBenchmark {

    private PaillierMath paillier;
    private Ciphertext pA, pB;

    private FheContext bfv;
    private FheContext ckks;
    private boolean nativeUp;

    @Setup(Level.Trial)
    public void setup() {
        // 2048 = the production default, so these numbers mean something.
        paillier = new PaillierMath(new PaillierKeyPair(2048));
        pA = paillier.encrypt(BigInteger.valueOf(1234L));
        pB = paillier.encrypt(BigInteger.valueOf(5678L));

        try {
            bfv = FheContext.bfv(8192);
            ckks = FheContext.ckks(8192, Math.pow(2, 40));
            nativeUp = true;
        } catch (Throwable t) {
            nativeUp = false;
        }
    }

    @TearDown(Level.Trial)
    public void tearDown() {
        if (nativeUp) {
            bfv.close();
            ckks.close();
        }
        BlindContext.clear();
    }

    // ── Paillier (pure Java) ─────────────────────────────────────────────────

    @Benchmark
    public Ciphertext paillierEncrypt() {
        return paillier.encrypt(BigInteger.valueOf(42L));
    }

    /** modPow over n² — the most expensive step on the read path. */
    @Benchmark
    public BigInteger paillierDecrypt() {
        return paillier.decryptSigned(pA);
    }

    /** Addition is a modular multiply: cheap, and the reason Paillier is worth having. */
    @Benchmark
    public Ciphertext paillierAdd() {
        return paillier.add(pA, pB);
    }

    // ── BFV ──────────────────────────────────────────────────────────────────

    @Benchmark
    public long bfvEncryptDecryptRoundTrip() {
        if (!nativeUp) return 0;
        try (var ct = new FheCiphertextNative(bfv.encryptLong(42L), bfv)) {
            return bfv.decryptLong(ct.handle());
        }
    }

    @Benchmark
    public long bfvAdd() {
        if (!nativeUp) return 0;
        try (var a = new FheCiphertextNative(bfv.encryptLong(1L), bfv);
             var b = new FheCiphertextNative(bfv.encryptLong(2L), bfv);
             var s = new FheCiphertextNative(bfv.add(a.handle(), b.handle()), bfv)) {
            return bfv.decryptLong(s.handle());
        }
    }

    /** Multiply is the expensive one, and the one that spends noise budget. */
    @Benchmark
    public long bfvMultiply() {
        if (!nativeUp) return 0;
        try (var a = new FheCiphertextNative(bfv.encryptLong(3L), bfv);
             var b = new FheCiphertextNative(bfv.encryptLong(4L), bfv);
             var p = new FheCiphertextNative(bfv.multiply(a.handle(), b.handle()), bfv)) {
            return bfv.decryptLong(p.handle());
        }
    }

    /** 8,192 values in one operation — divide the result by 8,192 for the per-value cost. */
    @Benchmark
    public long[] bfvBatchedAdd8192() {
        if (!nativeUp) return null;
        long[] v = new long[8192];
        try (var a = new FheCiphertextNative(bfv.encryptLongArray(v), bfv);
             var b = new FheCiphertextNative(bfv.encryptLongArray(v), bfv);
             var s = new FheCiphertextNative(bfv.add(a.handle(), b.handle()), bfv)) {
            return bfv.decryptLongArray(s.handle());
        }
    }

    // ── CKKS ─────────────────────────────────────────────────────────────────

    @Benchmark
    public double ckksEncryptDecryptRoundTrip() {
        if (!nativeUp) return 0;
        try (var ct = new FheCiphertextNative(ckks.encryptDouble(3.14159), ckks)) {
            return ckks.decryptDouble(ct.handle());
        }
    }

    /** 4,096 reals in one operation — the path that did not exist before the double[] bridge. */
    @Benchmark
    public double[] ckksBatchedAdd4096() {
        if (!nativeUp) return null;
        double[] v = new double[4096];
        try (var a = new FheCiphertextNative(ckks.encryptDoubleArray(v), ckks);
             var b = new FheCiphertextNative(ckks.encryptDoubleArray(v), ckks);
             var s = new FheCiphertextNative(ckks.add(a.handle(), b.handle()), ckks)) {
            return ckks.decryptDoubleArray(s.handle());
        }
    }
}

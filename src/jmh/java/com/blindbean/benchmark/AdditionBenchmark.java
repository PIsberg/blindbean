package com.blindbean.benchmark;

import com.blindbean.math.PaillierKeyPair;
import com.blindbean.math.PaillierMath;
import com.blindbean.math.PaillierVectorized;
import com.blindbean.core.Ciphertext;
import org.openjdk.jmh.annotations.*;

import java.math.BigInteger;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@State(Scope.Thread)
@Warmup(iterations = 2, time = 1)
@Measurement(iterations = 3, time = 1)
@Fork(1)
public class AdditionBenchmark {

    private long stdA;
    private long stdB;

    private BigInteger bigA;
    private BigInteger bigB;

    private PaillierMath paillier;
    private Ciphertext cA;
    private Ciphertext cB;

    // SIMD simulation variables
    private long[] vArrayA;
    private long[] vArrayB;
    private long[] vResult;
    private long modN2;

    @Setup
    public void setup() {
        stdA = 150000L;
        stdB = 250000L;

        bigA = BigInteger.valueOf(stdA);
        bigB = BigInteger.valueOf(stdB);

        PaillierKeyPair kp = new PaillierKeyPair(512); // Use 512 for bench
        paillier = new PaillierMath(kp);

        cA = paillier.encrypt(bigA);
        cB = paillier.encrypt(bigB);

        int lanes = 1000;
        vArrayA = new long[lanes];
        vArrayB = new long[lanes];
        vResult = new long[lanes];
        modN2 = kp.getN2().longValue();

        for (int i = 0; i < lanes; i++) {
            vArrayA[i] = (long) (Math.random() * Integer.MAX_VALUE);
            vArrayB[i] = (long) (Math.random() * Integer.MAX_VALUE);
        }
    }

    @Benchmark
    public long standardLongAddition() {
        return stdA + stdB;
    }

    @Benchmark
    public BigInteger standardBigIntegerAddition() {
        return bigA.add(bigB);
    }

    @Benchmark
    public Ciphertext paillierAdditionSingleThread() {
        return paillier.add(cA, cB);
    }

    @Benchmark
    @OperationsPerInvocation(1000)
    public void paillierVectorApiSimd() {
        // Simulates batch processing of modular additions using Vector API
        PaillierVectorized.batchAdd(vArrayA, vArrayB, vResult, modN2);
    }
}

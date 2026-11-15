package se.deversity.blindbean.math;

import se.deversity.vibetags.annotations.AIExplain;
import se.deversity.vibetags.annotations.AIMemoryBudget;
import se.deversity.vibetags.annotations.AIPerformance;
import se.deversity.vibetags.annotations.AIPure;
import se.deversity.vibetags.annotations.AIThreadSafe;

import java.math.BigInteger;
import jdk.incubator.vector.DoubleVector;
import jdk.incubator.vector.LongVector;
import jdk.incubator.vector.VectorMask;
import jdk.incubator.vector.VectorOperators;
import jdk.incubator.vector.VectorSpecies;

/**
 * A prototype Vector API implementation demonstrating SIMD acceleration for batch modular multiplication (Paillier addition).
 */
@AIPerformance
@AIThreadSafe(strategy = AIThreadSafe.Strategy.IMMUTABLE,
              note = "Stateless utility class — SPECIES is a compile-time constant; no instance state")
public class PaillierVectorized {
    private static final VectorSpecies<Long> SPECIES = LongVector.SPECIES_PREFERRED;
    private static final VectorSpecies<Double> DSPECIES = DoubleVector.SPECIES_PREFERRED;

    /**
     * Exclusive upper bound for {@code modN2} in {@link #batchAdd}: {@code 2^50}.
     *
     * <p>The SIMD path estimates the quotient {@code q ≈ a*b/n} in double precision and
     * recovers the exact remainder as {@code a*b - q*n} in wrapped 64-bit arithmetic.
     * With operands reduced below {@code 2^50}, the quotient estimate is within ±2 of the
     * true quotient and the intermediate remainder stays within {@code ±3n < 2^63}, so the
     * two's-complement computation is exact and a bounded fix-up step canonicalizes it.
     * Above this bound the double mantissa (53 bits) can no longer guarantee that window.
     */
    public static final long MAX_MODULUS = 1L << 50;

    /**
     * <b>Benchmark / testing only.</b> Batch Paillier addition using the Vector API:
     * computes {@code result[i] = (c1Array[i] * c2Array[i]) mod modN2} for every index,
     * with a fully vectorized Barrett-style reduction (floating-point reciprocal quotient
     * estimate plus exact integer fix-up) in each SIMD lane. The tail loop applies the
     * identical scalar reduction, so lane and tail results are bit-identical.
     *
     * <p><b>Limitations:</b> correct for any modulus in {@code [2, 2^50)} with both operand
     * arrays already reduced into {@code [0, modN2)}. Real Paillier ciphertexts are
     * 2048-bit numbers and cannot be represented in a {@code long} at all — for production
     * use {@link #batchAddBigInteger} instead.
     *
     * <p>Paillier addition is defined as {@code c1 * c2 mod n²} (modular multiplication of
     * ciphertexts).
     *
     * @param c1Array ciphertext array for the first operand; every element in {@code [0, modN2)}
     * @param c2Array ciphertext array for the second operand; same length, same range
     * @param result  output array, at least as long as the inputs
     * @param modN2   the modulus, in {@code [2, } {@link #MAX_MODULUS}{@code )}
     * @throws IllegalArgumentException if array lengths are inconsistent, the modulus is
     *         out of range, or any operand is not reduced into {@code [0, modN2)}
     */
    @AIExplain(AIExplain.ComplexityLevel.HIGH)
    @AIMemoryBudget(AIMemoryBudget.AllocationPolicy.NO_AUTOBOXING)
    public static void batchAdd(long[] c1Array, long[] c2Array, long[] result, long modN2) {
        if (c1Array.length != c2Array.length) {
            throw new IllegalArgumentException(
                "c1Array and c2Array must have the same length, got "
                + c1Array.length + " vs " + c2Array.length);
        }
        if (result.length < c1Array.length) {
            throw new IllegalArgumentException(
                "result array too small: " + result.length + " < " + c1Array.length);
        }
        if (modN2 < 2 || modN2 >= MAX_MODULUS) {
            throw new IllegalArgumentException(
                "modN2 must be in [2, 2^50), got " + modN2
                + "; use batchAddBigInteger for larger moduli");
        }

        int length = c1Array.length;
        requireReduced(c1Array, "c1Array", length, modN2);
        requireReduced(c2Array, "c2Array", length, modN2);
        int i = 0;
        int loopBound = SPECIES.loopBound(length);

        LongVector vn = LongVector.broadcast(SPECIES, modN2);
        DoubleVector dn = DoubleVector.broadcast(DSPECIES, (double) modN2);

        for (; i < loopBound; i += SPECIES.length()) {
            LongVector va = LongVector.fromArray(SPECIES, c1Array, i);
            LongVector vb = LongVector.fromArray(SPECIES, c2Array, i);

            // q ≈ floor(a*b / n), within ±2 of the true quotient (see MAX_MODULUS)
            DoubleVector da = (DoubleVector) va.convert(VectorOperators.L2D, 0);
            DoubleVector db = (DoubleVector) vb.convert(VectorOperators.L2D, 0);
            LongVector q = (LongVector) da.mul(db).div(dn).convert(VectorOperators.D2L, 0);

            // r = a*b - q*n: both products wrap mod 2^64, but the true difference lies in
            // (-3n, 3n) ⊂ (-2^63, 2^63), so the wrapped result is exact
            LongVector r = va.mul(vb).sub(q.mul(vn));

            // canonicalize into [0, n) — at most 2 corrections per direction
            VectorMask<Long> neg = r.compare(VectorOperators.LT, 0);
            while (neg.anyTrue()) {
                r = r.add(vn, neg);
                neg = r.compare(VectorOperators.LT, 0);
            }
            VectorMask<Long> ge = r.compare(VectorOperators.GE, vn);
            while (ge.anyTrue()) {
                r = r.sub(vn, ge);
                ge = r.compare(VectorOperators.GE, vn);
            }
            r.intoArray(result, i);
        }

        for (; i < length; i++) {
            result[i] = mulMod(c1Array[i], c2Array[i], modN2);
        }
    }

    /**
     * Refuses an operand array with any element outside {@code [0, modN2)}, before the SIMD loop.
     *
     * <p>A plain loop on purpose. The check used to be a vector compare of each loaded lane, and
     * the JDK 26 Windows CI leg refused in-range operands with it twice, on 2026-08-01 and
     * 2026-11-15, both times at index 8002 of a fresh 8192-element array of values under 1000:
     * {@code operand 223 in c1Array at index 8002 is not reduced into [0, 987654321012345)}, where
     * the rejected lane and the array both held 223. The compare's mask said out of range for a
     * value that was not. It did not reproduce in 43,200 local calls on JDK 26 (Windows, Intel,
     * with and without JaCoCo, on 4 pinned cores), so the cause is not established; a range check
     * made of scalar comparisons cannot disagree with the array it reads.
     */
    private static void requireReduced(long[] source, String operandName, int length, long modN2) {
        for (int index = 0; index < length; index++) {
            long operand = source[index];
            if (operand < 0 || operand >= modN2) {
                throw new IllegalArgumentException(
                    "operand " + operand + " in " + operandName + " at index " + index
                    + " is not reduced into [0, " + modN2 + ")");
            }
        }
    }

    /**
     * Scalar {@code (a * b) mod n} matching the SIMD lanes bit-for-bit: same
     * double-precision quotient estimate, same exact wrapped-difference fix-up.
     */
    private static long mulMod(long a, long b, long n) {
        if (a < 0 || a >= n) {
            throw new IllegalArgumentException("operand " + a + " is not reduced into [0, " + n + ")");
        }
        if (b < 0 || b >= n) {
            throw new IllegalArgumentException("operand " + b + " is not reduced into [0, " + n + ")");
        }
        long q = (long) ((double) a * (double) b / (double) n);
        long r = a * b - q * n;
        while (r < 0) r += n;
        while (r >= n) r -= n;
        return r;
    }

    /**
     * Production-correct batch Paillier addition: computes {@code c1[i] * c2[i] mod n²} for
     * every index using {@link BigInteger} arithmetic, which correctly handles full 2048-bit
     * Paillier ciphertexts without overflow.
     *
     * <p>Paillier addition in the encrypted domain is modular multiplication of ciphertexts:
     * {@code add(Enc(m1), Enc(m2)) = Enc(m1 + m2) = c1 * c2 mod n²}.
     *
     * @param c1Array ciphertext array for the first operand
     * @param c2Array ciphertext array for the second operand (must have the same length as c1Array)
     * @param n2      the Paillier modulus squared — obtain via {@link PaillierKeyPair#getN2()}
     * @return a new array where {@code result[i] = c1Array[i].multiply(c2Array[i]).mod(n2)}
     * @throws IllegalArgumentException if the input arrays have different lengths
     */
    @AIPerformance
    @AIPure
    public static BigInteger[] batchAddBigInteger(BigInteger[] c1Array, BigInteger[] c2Array, BigInteger n2) {
        if (c1Array.length != c2Array.length) {
            throw new IllegalArgumentException(
                "c1Array and c2Array must have the same length, got "
                + c1Array.length + " vs " + c2Array.length);
        }
        BigInteger[] result = new BigInteger[c1Array.length];
        for (int i = 0; i < c1Array.length; i++) {
            result[i] = c1Array[i].multiply(c2Array[i]).mod(n2);
        }
        return result;
    }
}

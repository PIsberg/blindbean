package com.blindbean.math;

import se.deversity.vibetags.annotations.AIDraft;
import se.deversity.vibetags.annotations.AIPerformance;
import se.deversity.vibetags.annotations.AIThreadSafe;

import java.math.BigInteger;
import jdk.incubator.vector.LongVector;
import jdk.incubator.vector.VectorSpecies;

/**
 * A prototype Vector API implementation demonstrating SIMD acceleration for batch modular multiplication (Paillier addition).
 */
@AIPerformance
@AIThreadSafe(strategy = AIThreadSafe.Strategy.IMMUTABLE,
              note = "Stateless utility class — SPECIES is a compile-time constant; no instance state")
public class PaillierVectorized {
    private static final VectorSpecies<Long> SPECIES = LongVector.SPECIES_PREFERRED;

    /**
     * <b>Benchmark / testing only.</b> Batch Paillier addition using the Vector API with
     * primitive {@code long} arithmetic as a stand-in for BigInteger-scale modular multiplication.
     *
     * <p><b>Limitations:</b> This implementation is only correct when all ciphertext values fit
     * in a signed 64-bit {@code long} and {@code modN2} is positive and fits in a {@code long}.
     * Real Paillier ciphertexts are 2048-bit numbers — this method silently overflows for those
     * inputs. <b>Do not use in production paths.</b> Use {@link #batchAddBigInteger} instead.
     *
     * <p>Paillier addition is defined as {@code c1 * c2 mod n²} (modular multiplication of
     * ciphertexts). The SIMD loop vectorises the multiply step; the tail loop handles the
     * remaining elements that don't fill a full SIMD lane.
     */
    @AIDraft(instructions = "Replace stand-in long arithmetic with true vectorized modular reduction: "
            + "implement Barrett or Montgomery reduction across SIMD lanes to handle BigInteger-scale "
            + "carry propagation. Each lane must reduce mod n² correctly; see PaillierKeyPair.getN2().")
    public static void batchAdd(long[] c1Array, long[] c2Array, long[] result, long modN2) {
        int length = c1Array.length;
        int i = 0;
        int loopBound = SPECIES.loopBound(length);

        for (; i < loopBound; i += SPECIES.length()) {
            LongVector v1 = LongVector.fromArray(SPECIES, c1Array, i);
            LongVector v2 = LongVector.fromArray(SPECIES, c2Array, i);
            v1.mul(v2).intoArray(result, i);
        }

        for (; i < length; i++) {
            result[i] = (c1Array[i] * c2Array[i]) % modN2;
        }
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

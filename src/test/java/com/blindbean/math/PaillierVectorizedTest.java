package com.blindbean.math;

import com.blindbean.core.Ciphertext;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Correctness tests for the SIMD modular-reduction path in {@link PaillierVectorized#batchAdd}.
 * Every SIMD result is checked against an independent {@link BigInteger} reference, so both
 * the vector lanes and the scalar tail are validated bit-for-bit.
 */
public class PaillierVectorizedTest {

    private static final Random RANDOM = new Random(0xB11FD8EA7L); // fixed seed for reproducibility

    private static long[] randomReduced(int length, long mod) {
        long[] values = new long[length];
        for (int i = 0; i < length; i++) {
            values[i] = RANDOM.nextLong(mod);
        }
        return values;
    }

    private static long[] referenceMulMod(long[] a, long[] b, long mod) {
        BigInteger m = BigInteger.valueOf(mod);
        long[] expected = new long[a.length];
        for (int i = 0; i < a.length; i++) {
            expected[i] = BigInteger.valueOf(a[i]).multiply(BigInteger.valueOf(b[i])).mod(m).longValueExact();
        }
        return expected;
    }

    private static void assertMatchesReference(int length, long mod) {
        long[] a = randomReduced(length, mod);
        long[] b = randomReduced(length, mod);
        long[] result = new long[length];
        PaillierVectorized.batchAdd(a, b, result, mod);
        assertArrayEquals(referenceMulMod(a, b, mod), result,
            "SIMD batchAdd must match BigInteger reference for length=" + length + ", mod=" + mod);
    }

    @Test
    public void matchesBigIntegerReferenceAcrossLengthsAndModuli() {
        long[] moduli = {
            2, 3, 97, 65537,
            987654321012345L,            // modulus used by the concurrency stress test
            (1L << 49) + 1,
            PaillierVectorized.MAX_MODULUS - 1 // worst case for the quotient estimate
        };
        int[] lengths = {1, 2, 7, 8, 9, 63, 64, 100, 1000}; // straddle SIMD lane boundaries
        for (long mod : moduli) {
            for (int length : lengths) {
                assertMatchesReference(length, mod);
            }
        }
    }

    @Test
    public void handlesMaximalOperandsAtMaximalModulus() {
        long mod = PaillierVectorized.MAX_MODULUS - 1;
        int length = 32;
        long[] a = new long[length];
        long[] b = new long[length];
        java.util.Arrays.fill(a, mod - 1);
        java.util.Arrays.fill(b, mod - 1);
        long[] result = new long[length];
        PaillierVectorized.batchAdd(a, b, result, mod);
        assertArrayEquals(referenceMulMod(a, b, mod), result);
    }

    @Test
    public void preservesPaillierHomomorphicProperty() {
        // A 24-bit key gives n² < 2^48, so real ciphertexts fit the SIMD path end-to-end.
        // With 12-bit primes the keygen preconditions (p ≠ q, gcd(n, φ(n)) = 1) can
        // occasionally fail, so retry until the key round-trips.
        PaillierKeyPair kp = workingTinyKeyPair();
        long n2 = kp.getN2().longValueExact();
        assertTrue(n2 < PaillierVectorized.MAX_MODULUS, "test key must produce n² below the SIMD bound");
        PaillierMath paillier = new PaillierMath(kp);

        int length = 16;
        long[] c1 = new long[length];
        long[] c2 = new long[length];
        long[] m1 = new long[length];
        long[] m2 = new long[length];
        for (int i = 0; i < length; i++) {
            m1[i] = RANDOM.nextLong(100);
            m2[i] = RANDOM.nextLong(100);
            c1[i] = encryptVerified(paillier, m1[i]);
            c2[i] = encryptVerified(paillier, m2[i]);
        }

        long[] sums = new long[length];
        PaillierVectorized.batchAdd(c1, c2, sums, n2);

        for (int i = 0; i < length; i++) {
            Ciphertext encryptedSum = Ciphertext.fromBytes(
                BigInteger.valueOf(sums[i]).toByteArray(), com.blindbean.annotations.Scheme.PAILLIER);
            assertEquals(BigInteger.valueOf(m1[i] + m2[i]), paillier.decrypt(encryptedSum),
                "decrypt(batchAdd(Enc(a), Enc(b))) must equal a + b at index " + i);
        }
    }

    private static PaillierKeyPair workingTinyKeyPair() {
        for (int attempt = 0; attempt < 20; attempt++) {
            try {
                PaillierKeyPair kp = new PaillierKeyPair(24);
                if (kp.getN().sqrt().pow(2).equals(kp.getN())) {
                    continue; // p == q — degenerate, decryption theorem does not hold
                }
                PaillierMath paillier = new PaillierMath(kp);
                BigInteger probe = BigInteger.valueOf(42);
                if (paillier.decrypt(paillier.encrypt(probe)).equals(probe)) {
                    return kp;
                }
            } catch (ArithmeticException degenerateKey) {
                // gcd precondition violated for this prime pair; try again
            }
        }
        throw new AssertionError("could not generate a functional 24-bit Paillier key pair in 20 attempts");
    }

    /**
     * With 12-bit primes, an encryption nonce occasionally shares a factor with n,
     * making that single ciphertext undecryptable — retry until the round-trip holds.
     * (For real key sizes this probability is cryptographically negligible.)
     */
    private static long encryptVerified(PaillierMath paillier, long message) {
        BigInteger m = BigInteger.valueOf(message);
        for (int attempt = 0; attempt < 10; attempt++) {
            Ciphertext c = paillier.encrypt(m);
            if (paillier.decrypt(c).equals(m)) {
                return new BigInteger(1, c.getBytes()).longValueExact();
            }
        }
        throw new AssertionError("could not produce a decryptable tiny-key ciphertext for " + message);
    }

    @Test
    public void rejectsMismatchedAndUndersizedArrays() {
        assertThrows(IllegalArgumentException.class,
            () -> PaillierVectorized.batchAdd(new long[3], new long[4], new long[4], 97));
        assertThrows(IllegalArgumentException.class,
            () -> PaillierVectorized.batchAdd(new long[4], new long[4], new long[3], 97));
    }

    @Test
    public void rejectsModulusOutOfRange() {
        long[] a = new long[4];
        assertThrows(IllegalArgumentException.class, () -> PaillierVectorized.batchAdd(a, a, new long[4], 1));
        assertThrows(IllegalArgumentException.class, () -> PaillierVectorized.batchAdd(a, a, new long[4], 0));
        assertThrows(IllegalArgumentException.class, () -> PaillierVectorized.batchAdd(a, a, new long[4], -97));
        assertThrows(IllegalArgumentException.class,
            () -> PaillierVectorized.batchAdd(a, a, new long[4], PaillierVectorized.MAX_MODULUS));
    }

    @Test
    public void rejectsUnreducedOperands() {
        // Long enough to hit the SIMD loop and the scalar tail with bad values in each
        int length = 67;
        long mod = 65537;

        long[] good = randomReduced(length, mod);
        long[] badInSimd = randomReduced(length, mod);
        badInSimd[0] = mod; // first vector
        assertThrows(IllegalArgumentException.class,
            () -> PaillierVectorized.batchAdd(badInSimd, good, new long[length], mod));

        long[] badInTail = randomReduced(length, mod);
        badInTail[length - 1] = -1; // scalar tail
        assertThrows(IllegalArgumentException.class,
            () -> PaillierVectorized.batchAdd(good, badInTail, new long[length], mod));
    }

    @Test
    public void batchAddBigIntegerRejectsMismatchedLengths() {
        assertThrows(IllegalArgumentException.class, () -> PaillierVectorized.batchAddBigInteger(
            new BigInteger[]{BigInteger.ONE}, new BigInteger[]{BigInteger.ONE, BigInteger.TWO}, BigInteger.valueOf(97)));
    }
}

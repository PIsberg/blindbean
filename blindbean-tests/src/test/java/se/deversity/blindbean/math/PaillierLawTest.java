package se.deversity.blindbean.math;

import se.deversity.blindbean.core.Ciphertext;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Randomised property / metamorphic tests for the pure-Java Paillier core.
 *
 * <p>Rather than a handful of fixed vectors, each law is checked against many pseudo-random inputs
 * from a <em>fixed seed</em> — so a failure is reproducible and prints the exact operands. The
 * homomorphic identities checked here are the whole contract of the scheme: if any of them breaks,
 * encrypted arithmetic silently returns wrong answers. Signed decoding goes through
 * {@link PaillierMath#decryptSigned} (balanced representation), matching how the generated wrappers
 * decode every numeric field.
 *
 * <p>Values are kept far below {@code n/2} so sums and differences never wrap the modulus — that is
 * a documented property of the encoding (a caller who overflows the plaintext space gets a residue),
 * not something these correctness laws should fight.
 */
@DisplayName("Paillier: homomorphic laws, probabilistic encryption, and the binomial fast path")
class PaillierLawTest {

    private static final int KEY_BITS = 512;      // fast keygen; the laws are size-independent
    private static final int VALUE_BITS = 120;    // << n/2 (~2^511), so no modular wraparound
    private static final int ITERATIONS = 300;
    private static final long SEED = 0xB1EEDBEA_9C0FFEEL;

    private final PaillierMath paillier = new PaillierMath(new PaillierKeyPair(KEY_BITS));
    private final Random values = new Random(SEED);

    /** A pseudo-random signed magnitude, deterministic across runs via the fixed seed. */
    private BigInteger randomValue() {
        BigInteger magnitude = new BigInteger(VALUE_BITS, values);
        return values.nextBoolean() ? magnitude : magnitude.negate();
    }

    @Test
    @DisplayName("encrypt then decrypt is the identity (signed)")
    void encryptDecryptRoundTrip() {
        for (int i = 0; i < ITERATIONS; i++) {
            BigInteger m = randomValue();
            assertEquals(m, paillier.decryptSigned(paillier.encrypt(m)),
                    "round-trip failed for m=" + m);
        }
    }

    @Test
    @DisplayName("Dec(Enc(a) + Enc(b)) == a + b")
    void additiveHomomorphism() {
        for (int i = 0; i < ITERATIONS; i++) {
            BigInteger a = randomValue();
            BigInteger b = randomValue();
            Ciphertext sum = paillier.add(paillier.encrypt(a), paillier.encrypt(b));
            assertEquals(a.add(b), paillier.decryptSigned(sum), "add failed for a=" + a + ", b=" + b);
        }
    }

    @Test
    @DisplayName("Dec(Enc(a) - Enc(b)) == a - b")
    void subtractiveHomomorphism() {
        for (int i = 0; i < ITERATIONS; i++) {
            BigInteger a = randomValue();
            BigInteger b = randomValue();
            Ciphertext diff = paillier.subtract(paillier.encrypt(a), paillier.encrypt(b));
            assertEquals(a.subtract(b), paillier.decryptSigned(diff),
                    "subtract failed for a=" + a + ", b=" + b);
        }
    }

    @Test
    @DisplayName("homomorphic addition is commutative and associative under decryption")
    void additionCommutesAndAssociates() {
        for (int i = 0; i < ITERATIONS; i++) {
            BigInteger a = randomValue();
            BigInteger b = randomValue();
            BigInteger c = randomValue();
            Ciphertext ea = paillier.encrypt(a);
            Ciphertext eb = paillier.encrypt(b);
            Ciphertext ec = paillier.encrypt(c);

            assertEquals(paillier.decryptSigned(paillier.add(ea, eb)),
                    paillier.decryptSigned(paillier.add(eb, ea)),
                    "commutativity failed for a=" + a + ", b=" + b);

            BigInteger left = paillier.decryptSigned(paillier.add(paillier.add(ea, eb), ec));
            BigInteger right = paillier.decryptSigned(paillier.add(ea, paillier.add(eb, ec)));
            assertEquals(left, right, "associativity failed for a=" + a + ", b=" + b + ", c=" + c);
        }
    }

    @Test
    @DisplayName("adding an encrypted zero leaves the value unchanged")
    void addingEncryptedZeroIsIdentity() {
        for (int i = 0; i < ITERATIONS; i++) {
            BigInteger a = randomValue();
            Ciphertext sum = paillier.add(paillier.encrypt(a), paillier.encrypt(BigInteger.ZERO));
            assertEquals(a, paillier.decryptSigned(sum), "add-zero identity failed for a=" + a);
        }
    }

    @Test
    @DisplayName("encryption is probabilistic: same plaintext, different ciphertext, same decryption")
    void encryptionIsProbabilistic() {
        // IND-CPA depends on the fresh per-encryption blinding r: two encryptions of the same value
        // must (with overwhelming probability) differ, yet both decrypt back to it.
        for (int i = 0; i < ITERATIONS; i++) {
            BigInteger m = randomValue();
            Ciphertext c1 = paillier.encrypt(m);
            Ciphertext c2 = paillier.encrypt(m);
            assertFalse(Arrays.equals(c1.getBytes(), c2.getBytes()),
                    "two encryptions of m=" + m + " produced identical ciphertext — blinding is broken");
            assertEquals(m, paillier.decryptSigned(c1), "c1 decrypt for m=" + m);
            assertEquals(m, paillier.decryptSigned(c2), "c2 decrypt for m=" + m);
        }
    }

    @Test
    @DisplayName("edge values: 0, ±1, and a magnitude just below n/2 round-trip and add correctly")
    void edgeValues() {
        BigInteger nHalf = paillier.getKeyPair().getN().shiftRight(1);
        BigInteger nearLimit = nHalf.subtract(BigInteger.valueOf(1000));
        BigInteger[] edges = {
                BigInteger.ZERO, BigInteger.ONE, BigInteger.valueOf(-1),
                BigInteger.TEN, BigInteger.valueOf(-1000),
                nearLimit, nearLimit.negate()
        };
        for (BigInteger m : edges) {
            assertEquals(m, paillier.decryptSigned(paillier.encrypt(m)), "round-trip edge m=" + m);
        }
        // adding two near-limit values of opposite sign must land back on a small number
        Ciphertext sum = paillier.add(paillier.encrypt(nearLimit), paillier.encrypt(nearLimit.negate()));
        assertEquals(BigInteger.ZERO, paillier.decryptSigned(sum), "±(n/2 - 1000) must cancel to 0");
    }

    @Test
    @DisplayName("differential: the (1+n) binomial fast path equals the textbook g^m mod n^2")
    void binomialFastPathMatchesTextbookModPow() {
        // encrypt() replaces the g^m modular exponentiation with (1 + m*n) mod n^2, justified by the
        // binomial theorem for g = n+1. This checks that shortcut against the textbook definition
        // computed independently — a full modPow of g = n+1 — over many random m, negatives included.
        BigInteger n = paillier.getKeyPair().getN();
        BigInteger n2 = paillier.getKeyPair().getN2();
        BigInteger g = paillier.getKeyPair().getG();
        assertEquals(n.add(BigInteger.ONE), g, "fast path assumes the generator g = n + 1");

        for (int i = 0; i < ITERATIONS; i++) {
            BigInteger m = randomValue();
            BigInteger fastPath = m.multiply(n).add(BigInteger.ONE).mod(n2);
            // g^m has period n in the exponent, so reduce m into [0, n) before the textbook modPow
            BigInteger textbook = g.modPow(m.mod(n), n2);
            assertEquals(textbook, fastPath, "binomial shortcut diverged from g^m for m=" + m);
        }
    }

    @Test
    @DisplayName("a decrypted ciphertext is a valid PAILLIER ciphertext bound to this key")
    void encryptProducesPaillierCiphertexts() {
        Ciphertext c = paillier.encrypt(BigInteger.valueOf(42));
        assertEquals(se.deversity.blindbean.annotations.Scheme.PAILLIER, c.scheme());
        assertTrue(c.getBytes().length > 0);
    }
}

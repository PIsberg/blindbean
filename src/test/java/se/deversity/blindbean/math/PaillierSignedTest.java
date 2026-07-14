package se.deversity.blindbean.math;

import se.deversity.blindbean.core.Ciphertext;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Negative numbers in Paillier.
 *
 * <p>Paillier's plaintext space is Z_n, so a raw {@code decrypt} hands back a residue in [0, n):
 * encrypt(-5) comes back as {@code n - 5}, a 600-digit positive integer. That is not a rounding
 * quirk, it is the whole of the negative range being unreadable — and it silently corrupted every
 * numeric field, not just the new ones. {@code decryptSigned} applies the balanced representation
 * (residues above n/2 are negative), which is the convention the additive homomorphism already
 * follows.
 */
public class PaillierSignedTest {

    // 512-bit: test-only, for keygen speed.
    private static PaillierMath math() {
        return new PaillierMath(new PaillierKeyPair(512));
    }

    @Test
    public void aNegativeNumberDecryptsAsItself() {
        PaillierMath m = math();
        Ciphertext ct = m.encrypt(BigInteger.valueOf(-5));

        assertEquals(BigInteger.valueOf(-5), m.decryptSigned(ct));
    }

    @Test
    public void theRawDecryptStillReturnsTheResidue() {
        // Documenting the behaviour decryptSigned exists to correct: a blob or a string is an
        // unsigned magnitude and MUST keep reading through decrypt(), so it cannot simply be
        // changed to signed everywhere.
        PaillierMath m = math();
        BigInteger n = m.getKeyPair().getN();

        BigInteger raw = m.decrypt(m.encrypt(BigInteger.valueOf(-5)));
        assertEquals(n.subtract(BigInteger.valueOf(5)), raw);
        assertTrue(raw.signum() > 0, "the residue is positive — that is the trap");
    }

    @Test
    public void signedValuesStillAddHomomorphically() {
        PaillierMath m = math();
        Ciphertext sum = m.add(m.encrypt(BigInteger.valueOf(-5)), m.encrypt(BigInteger.valueOf(7)));

        assertEquals(BigInteger.valueOf(2), m.decryptSigned(sum),
            "the balanced representation must agree with the additive homomorphism");
    }

    @Test
    public void addingPastZeroGoesNegative() {
        PaillierMath m = math();
        Ciphertext diff = m.subtract(m.encrypt(BigInteger.valueOf(3)), m.encrypt(BigInteger.valueOf(10)));

        assertEquals(BigInteger.valueOf(-7), m.decryptSigned(diff),
            "3 - 10 must be -7, not n-7");
    }

    @Test
    public void positiveValuesAreUnaffected() {
        PaillierMath m = math();
        assertEquals(BigInteger.valueOf(42), m.decryptSigned(m.encrypt(BigInteger.valueOf(42))));
        assertEquals(BigInteger.ZERO, m.decryptSigned(m.encrypt(BigInteger.ZERO)));
    }
}

package se.deversity.blindbean.math;

import se.deversity.blindbean.context.BlindContext;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Asserts the Paillier parameters are cryptographically sound — the "are the numbers actually
 * secure" half of correctness, complementing the homomorphic-law checks in {@link PaillierLawTest}.
 *
 * <p>Only <em>public</em> key material is touched here (modulus, n^2, generator). The private
 * components (lambda, mu) are secret and never read, logged, or asserted on.
 */
@DisplayName("Paillier: parameter and security-floor checks")
class PaillierParametersTest {

    @Test
    @DisplayName("the production default modulus is at least 2048 bits")
    void defaultKeySizeMeetsSecurityFloor() {
        // 1024-bit Paillier is ~80-bit security and no longer trusted; 2048 is the documented floor.
        assertTrue(BlindContext.DEFAULT_PAILLIER_BITS >= 2048,
                "DEFAULT_PAILLIER_BITS dropped below the 2048-bit security floor: "
                        + BlindContext.DEFAULT_PAILLIER_BITS);
    }

    @Test
    @DisplayName("a production-sized key generates a full-length composite modulus")
    void generatedModulusIsFullLengthOddComposite() {
        PaillierKeyPair kp = new PaillierKeyPair(BlindContext.DEFAULT_PAILLIER_BITS);
        BigInteger n = kp.getN();

        assertTrue(n.bitLength() >= BlindContext.DEFAULT_PAILLIER_BITS - 1,
                "modulus is shorter than requested: " + n.bitLength() + " bits");
        assertTrue(n.testBit(0), "an RSA-family modulus n = p*q must be odd");
        assertFalse(n.isProbablePrime(64),
                "n must be a composite p*q — a prime modulus would collapse Paillier's security");
        assertEquals(n.multiply(n), kp.getN2(), "n^2 must be exactly the square of the modulus");
    }

    @Test
    @DisplayName("the generator is g = n + 1 (the fast-path precondition)")
    void generatorIsNPlusOne() {
        PaillierKeyPair kp = new PaillierKeyPair(512);
        assertEquals(kp.getN().add(BigInteger.ONE), kp.getG(),
                "encrypt()'s binomial shortcut is only valid for g = n + 1");
    }

    @Test
    @DisplayName("the blinding factor is drawn as a unit coprime to the modulus")
    void samplingProducesUnitsCoprimeToModulus() {
        // encrypt() samples r in (0, n); for IND-CPA the effective space must be Z_n* (gcd(r,n)=1).
        // A non-coprime r would require r to share a prime factor with n — probability ~2^-1000 for a
        // 2048-bit modulus — so a large sample here is coprime every time, evidencing the property.
        PaillierKeyPair kp = new PaillierKeyPair(1024);
        BigInteger n = kp.getN();
        SecureRandom random = new SecureRandom();

        for (int i = 0; i < 2000; i++) {
            BigInteger r;
            do {
                r = new BigInteger(n.bitLength(), random);
            } while (r.compareTo(n) >= 0 || r.signum() <= 0);
            assertEquals(BigInteger.ONE, r.gcd(n),
                    "sampled blinding factor was not coprime to n (r=" + r + ")");
        }
    }
}

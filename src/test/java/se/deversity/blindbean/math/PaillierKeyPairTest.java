package se.deversity.blindbean.math;

import se.deversity.blindbean.annotations.Scheme;
import se.deversity.blindbean.core.Ciphertext;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * Key-generation invariants for {@link PaillierKeyPair}.
 *
 * <p>Assertions are confined to the public modulus. The private components are never read,
 * printed, or asserted on.
 */
public class PaillierKeyPairTest {

    /**
     * Paillier requires n = p*q with p != q. A key that drew the same prime twice has n = p^2,
     * which is a perfect square — and gcd(n, phi(n)) = p rather than 1, so the scheme's
     * correctness condition no longer holds. Small bit lengths make the collision reachable,
     * which is exactly where the guard has to hold.
     */
    @Test
    public void modulusIsNeverAPerfectSquare() {
        for (int i = 0; i < 200; i++) {
            BigInteger n = new PaillierKeyPair(32).getN();
            BigInteger root = n.sqrt();
            assertNotEquals(n, root.multiply(root),
                "n must be a product of two distinct primes, not p^2");
        }
    }

    @Test
    public void freshlyGeneratedKeysEncryptAndDecrypt() {
        for (int i = 0; i < 50; i++) {
            PaillierMath math = new PaillierMath(new PaillierKeyPair(64));
            BigInteger message = BigInteger.valueOf(1234L);

            Ciphertext ct = math.encrypt(message);
            assertEquals(Scheme.PAILLIER, ct.scheme());
            assertEquals(message, math.decrypt(ct), "every generated key must round-trip");
        }
    }
}

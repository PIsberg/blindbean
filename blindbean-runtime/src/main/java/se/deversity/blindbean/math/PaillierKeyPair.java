package se.deversity.blindbean.math;

import java.math.BigInteger;
import java.security.SecureRandom;

import se.deversity.vibetags.annotations.AIImmutable;
import se.deversity.vibetags.annotations.AILocked;
import se.deversity.vibetags.annotations.AIPrivacy;
import se.deversity.vibetags.annotations.AISchemaSafe;
import se.deversity.vibetags.annotations.AISecure;
import se.deversity.vibetags.annotations.AISecureLogging;

@AIImmutable(note = "All key material is computed once in the constructor and stored in final fields; never add setters, non-final fields, or post-construction mutation")
@AIPrivacy(reason = "Contains RSA-family private key components (lambda, mu) — never log values, include in test fixtures, or expose in suggestions")
@AISecure(aspect = "key-generation")
@AISchemaSafe
public class PaillierKeyPair implements java.io.Serializable {
    @AILocked(reason = "Serialization UID — changing this breaks deserialization of persisted KeyBundle files")
    private static final long serialVersionUID = 1L;

    private final BigInteger n;
    private final BigInteger n2; // n^2
    private final BigInteger g;

    // Private key components
    @AISecureLogging(AISecureLogging.MaskingPolicy.OMIT)
    private final BigInteger lambda;
    @AISecureLogging(AISecureLogging.MaskingPolicy.OMIT)
    private final BigInteger mu;

    public PaillierKeyPair(int bitLength) {
        SecureRandom random = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(bitLength / 2, random);
        BigInteger q;
        // Paillier requires two *distinct* primes: p == q gives n = p^2, whose gcd with
        // phi(n) is p rather than 1, so the scheme's correctness condition no longer holds
        // and mu = L(...)^-1 mod n is not invertible. Vanishingly rare at the 1024-bit
        // default, but reachable at the small bit lengths this constructor accepts.
        do {
            q = BigInteger.probablePrime(bitLength / 2, random);
        } while (q.equals(p));

        this.n = p.multiply(q);
        this.n2 = n.multiply(n);
        this.g = n.add(BigInteger.ONE); // simple mapping g = n+1

        BigInteger pMinus1 = p.subtract(BigInteger.ONE);
        BigInteger qMinus1 = q.subtract(BigInteger.ONE);
        this.lambda = pMinus1.multiply(qMinus1).divide(pMinus1.gcd(qMinus1)); // lcm(p-1, q-1)

        BigInteger l = g.modPow(lambda, n2).subtract(BigInteger.ONE).divide(n);
        this.mu = l.modInverse(n);
    }

    public BigInteger getN() { return n; }
    public BigInteger getN2() { return n2; }
    public BigInteger getG() { return g; }
    public BigInteger getLambda() { return lambda; }
    public BigInteger getMu() { return mu; }
}

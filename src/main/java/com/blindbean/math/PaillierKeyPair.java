package com.blindbean.math;

import java.math.BigInteger;
import java.security.SecureRandom;

public class PaillierKeyPair implements java.io.Serializable {
    private static final long serialVersionUID = 1L;

    private final BigInteger n;
    private final BigInteger n2; // n^2
    private final BigInteger g;

    // Private key components
    private final BigInteger lambda;
    private final BigInteger mu;

    public PaillierKeyPair(int bitLength) {
        SecureRandom random = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(bitLength / 2, random);
        BigInteger q = BigInteger.probablePrime(bitLength / 2, random);

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

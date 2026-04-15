package com.blindbean.math;

import com.blindbean.core.Ciphertext;
import com.blindbean.annotations.Scheme;

import java.math.BigInteger;
import java.security.SecureRandom;

public class PaillierMath {
    private final SecureRandom random = new SecureRandom();
    private final PaillierKeyPair keyPair;

    public PaillierMath(PaillierKeyPair keyPair) {
        this.keyPair = keyPair;
    }

    public Ciphertext encrypt(BigInteger m) {
        BigInteger r;
        do {
            r = new BigInteger(keyPair.getN().bitLength(), random);
        } while (r.compareTo(keyPair.getN()) >= 0 || r.compareTo(BigInteger.ZERO) <= 0);

        // c = g^m * r^n mod n^2
        BigInteger gm = keyPair.getG().modPow(m, keyPair.getN2());
        BigInteger rn = r.modPow(keyPair.getN(), keyPair.getN2());
        BigInteger c = gm.multiply(rn).mod(keyPair.getN2());

        return Ciphertext.fromBytes(c.toByteArray(), Scheme.PAILLIER);
    }

    public BigInteger decrypt(Ciphertext c) {
        if (c.scheme() != Scheme.PAILLIER) throw new IllegalArgumentException();
        BigInteger cipher = new BigInteger(1, c.getBytes());

        // m = L(c^lambda mod n^2) * mu mod n
        BigInteger u = cipher.modPow(keyPair.getLambda(), keyPair.getN2());
        BigInteger l = u.subtract(BigInteger.ONE).divide(keyPair.getN());
        return l.multiply(keyPair.getMu()).mod(keyPair.getN());
    }

    public Ciphertext add(Ciphertext a, Ciphertext b) {
        if (a.scheme() != Scheme.PAILLIER || b.scheme() != Scheme.PAILLIER) {
            throw new IllegalArgumentException();
        }
        BigInteger numA = new BigInteger(a.getBytes());
        BigInteger numB = new BigInteger(b.getBytes());

        // Addition in Paillier is multiplication of ciphertexts mod n^2
        BigInteger result = numA.multiply(numB).mod(keyPair.getN2());
        return Ciphertext.fromBytes(result.toByteArray(), Scheme.PAILLIER);
    }

    public Ciphertext subtract(Ciphertext a, Ciphertext b) {
        if (a.scheme() != Scheme.PAILLIER || b.scheme() != Scheme.PAILLIER) {
            throw new IllegalArgumentException();
        }
        BigInteger numA = new BigInteger(a.getBytes());
        BigInteger numB = new BigInteger(b.getBytes());

        // Subtraction in Paillier is multiplication by the modular inverse mod n^2
        BigInteger inverseB = numB.modInverse(keyPair.getN2());
        BigInteger result = numA.multiply(inverseB).mod(keyPair.getN2());
        return Ciphertext.fromBytes(result.toByteArray(), Scheme.PAILLIER);
    }
}

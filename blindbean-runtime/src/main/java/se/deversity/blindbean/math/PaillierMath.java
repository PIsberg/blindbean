package se.deversity.blindbean.math;

import se.deversity.blindbean.core.Ciphertext;
import se.deversity.blindbean.core.KeyTag;
import se.deversity.blindbean.annotations.Scheme;

import java.math.BigInteger;
import java.security.SecureRandom;

import se.deversity.vibetags.annotations.AIExplain;
import se.deversity.vibetags.annotations.AIPerformance;
import se.deversity.vibetags.annotations.AISecure;
import se.deversity.vibetags.annotations.AIStrictExceptions;

@AISecure(aspect = "paillier-encryption")
@AIStrictExceptions
@AIPerformance(constraint = "Encryption/decryption are modPow-heavy over large BigIntegers — never introduce extra copies, unnecessary allocations, or redundant modular reductions on the hot path")
@AIExplain(AIExplain.ComplexityLevel.HIGH)
public class PaillierMath {
    private final SecureRandom random = new SecureRandom();
    private final PaillierKeyPair keyPair;

    /**
     * This key generation's fingerprint, stamped into every ciphertext it produces and checked on
     * every ciphertext it consumes. Derived once from the <em>public</em> modulus, so it costs one
     * SHA-256 per PaillierMath rather than anything on the hot path — the wrap/unwrap that remains
     * there is a 22-byte header copy against a modPow over a 1024-bit+ modulus.
     */
    private final byte[] keyTag;

    public PaillierMath(PaillierKeyPair keyPair) {
        this.keyPair = keyPair;
        this.keyTag = KeyTag.derive(keyPair.getN().toByteArray());
    }

    public PaillierKeyPair getKeyPair() {
        return keyPair;
    }

    /** This key generation's fingerprint. A digest of the public modulus, not key material. */
    public byte[] keyTag() {
        return keyTag.clone();
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

        return Ciphertext.fromBytes(KeyTag.wrap(keyTag, c.toByteArray()), Scheme.PAILLIER);
    }

    public BigInteger decrypt(Ciphertext c) {
        if (c.scheme() != Scheme.PAILLIER) {
            throw new IllegalArgumentException(
                "PaillierMath.decrypt requires a PAILLIER ciphertext, got " + c.scheme());
        }
        // Refuse a ciphertext from another key generation. Nothing below would fail on one:
        // c^lambda = 1 (mod n) holds for any c coprime to n, so L() divides exactly and the
        // wrong key yields a plausible wrong plaintext rather than an error.
        BigInteger cipher = new BigInteger(1, unwrap(c, "decrypt this ciphertext"));

        // m = L(c^lambda mod n^2) * mu mod n
        BigInteger u = cipher.modPow(keyPair.getLambda(), keyPair.getN2());
        BigInteger l = u.subtract(BigInteger.ONE).divide(keyPair.getN());
        return l.multiply(keyPair.getMu()).mod(keyPair.getN());
    }

    /**
     * Decrypts to a <em>signed</em> value.
     *
     * <p>Paillier's plaintext space is Z_n, so {@link #decrypt} returns a residue in [0, n) —
     * meaning a negative number comes back as {@code n - |m|}, a several-hundred-digit positive
     * integer. Every numeric type has to undo that, or -5 decrypts as nonsense: the balanced
     * representation treats residues above n/2 as negative, which is the convention the additive
     * homomorphism is consistent with (encrypt(-5) then add 7 still gives 2).
     *
     * <p>Only meaningful for values that are genuinely numbers. Strings and byte blobs are encoded
     * as unsigned magnitudes and must use {@link #decrypt}, or a blob whose leading bit is set would
     * be read as a negative number.
     */
    public BigInteger decryptSigned(Ciphertext c) {
        BigInteger m = decrypt(c);
        BigInteger n = keyPair.getN();
        return m.compareTo(n.shiftRight(1)) > 0 ? m.subtract(n) : m;
    }

    public Ciphertext add(Ciphertext a, Ciphertext b) {
        if (a.scheme() != Scheme.PAILLIER || b.scheme() != Scheme.PAILLIER) {
            throw new IllegalArgumentException(
                "PaillierMath.add requires PAILLIER ciphertexts, got "
                + a.scheme() + " and " + b.scheme());
        }
        // Ciphertext bytes are an unsigned magnitude — parse with signum 1, matching
        // decrypt(); the signed constructor misreads magnitudes whose top bit is set
        BigInteger numA = new BigInteger(1, unwrap(a, "add this ciphertext"));
        BigInteger numB = new BigInteger(1, unwrap(b, "add this ciphertext"));

        // Addition in Paillier is multiplication of ciphertexts mod n^2
        BigInteger result = numA.multiply(numB).mod(keyPair.getN2());
        return Ciphertext.fromBytes(KeyTag.wrap(keyTag, result.toByteArray()), Scheme.PAILLIER);
    }

    public Ciphertext subtract(Ciphertext a, Ciphertext b) {
        if (a.scheme() != Scheme.PAILLIER || b.scheme() != Scheme.PAILLIER) {
            throw new IllegalArgumentException(
                "PaillierMath.subtract requires PAILLIER ciphertexts, got "
                + a.scheme() + " and " + b.scheme());
        }
        BigInteger numA = new BigInteger(1, unwrap(a, "subtract this ciphertext"));
        BigInteger numB = new BigInteger(1, unwrap(b, "subtract this ciphertext"));

        // Subtraction in Paillier is multiplication by the modular inverse mod n^2
        BigInteger inverseB = numB.modInverse(keyPair.getN2());
        BigInteger result = numA.multiply(inverseB).mod(keyPair.getN2());
        return Ciphertext.fromBytes(KeyTag.wrap(keyTag, result.toByteArray()), Scheme.PAILLIER);
    }

    /**
     * Strips the key-generation header, refusing a ciphertext stamped with a different generation.
     * An unstamped (pre-{@link KeyTag}) payload is accepted as legacy and returned whole.
     */
    private byte[] unwrap(Ciphertext c, String operation) {
        return KeyTag.verifyAndUnwrap(c.getBytes(), keyTag, operation);
    }
}

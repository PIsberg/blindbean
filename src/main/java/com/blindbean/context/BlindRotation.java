package com.blindbean.context;

import com.blindbean.annotations.Scheme;
import com.blindbean.core.Ciphertext;
import com.blindbean.math.PaillierKeyPair;
import com.blindbean.math.PaillierMath;

import se.deversity.vibetags.annotations.AIIdempotent;
import se.deversity.vibetags.annotations.AIPrivacy;
import se.deversity.vibetags.annotations.AIPublicAPI;
import se.deversity.vibetags.annotations.AISecure;
import se.deversity.vibetags.annotations.AITestDriven;
import se.deversity.vibetags.annotations.AIThreadSafe;

import java.math.BigInteger;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;

/**
 * A key-rotation session: re-encrypts ciphertexts from one key generation to the next.
 *
 * <p>Homomorphic ciphertexts are bound to the keys that produced them and there is no in-place
 * re-key, so rotation is necessarily decrypt-then-encrypt. Doing that by hand against
 * {@link BlindContext} is awkward — it holds a single key set per thread, so callers had to
 * decrypt every value into plaintext, swap the context, and re-encrypt, leaving the whole
 * dataset in the clear in the meantime. A rotation session instead holds both key generations
 * side by side as ordinary objects, so plaintext exists only inside {@link #rotate(Ciphertext)}
 * and the thread-local context is not disturbed until {@link #commit()}.
 *
 * <pre>{@code
 * PaillierKeyPair next = new PaillierKeyPair(1024);
 * try (BlindRotation rotation = BlindRotation.fromCurrent(next)) {
 *     for (Wallet w : repository.findAll()) {
 *         new WalletBlindWrapper(w).rotateBalance(rotation);
 *         repository.save(w);
 *     }
 *     rotation.commit();                  // installs the new keys on this thread
 *     BlindContext.exportKeys("keys.bin");
 * }
 * }</pre>
 *
 * <p>Rotation is <em>not</em> atomic across your datastore: {@link #rotate(Ciphertext)} hands
 * back a re-encrypted value, but persisting it is yours to do, and a crash midway leaves some
 * rows under the old keys and some under the new. Keep the old bundle until the batch has been
 * verified, and retire it only afterwards.
 *
 * <p>BFV and CKKS rotation is not implemented yet; the corresponding factories fail fast rather
 * than pretending to rotate.
 */
@AIPublicAPI
@AISecure(aspect = "key-rotation")
@AIPrivacy(reason = "Holds two generations of Paillier private key material — never log the key pairs, "
                  + "the decrypted plaintext, or expose them in fixtures")
@AIThreadSafe(strategy = AIThreadSafe.Strategy.IMMUTABLE,
              note = "Both PaillierMath instances are effectively immutable and their SecureRandom is "
                   + "thread-safe, so rotate() may be called concurrently; the counter is an AtomicLong "
                   + "and commit()/close() are guarded by the session monitor")
@AITestDriven(coverageGoal = 90, testLocation = "src/test/java/com/blindbean/context")
public final class BlindRotation implements AutoCloseable {

    private final PaillierMath source;
    private final PaillierMath target;
    private final PaillierKeyPair targetKeys;
    private final AtomicLong rotated = new AtomicLong();

    private volatile boolean closed = false;
    private volatile boolean committed = false;

    private BlindRotation(PaillierKeyPair sourceKeys, PaillierKeyPair targetKeys) {
        if (sourceKeys.getN().equals(targetKeys.getN())) {
            throw new IllegalArgumentException(
                "Rotation source and target are the same key — rotating onto the same modulus "
                + "re-encrypts nothing and would retire a bundle that is still in use. "
                + "Generate a fresh PaillierKeyPair for the target.");
        }
        this.source     = new PaillierMath(sourceKeys);
        this.target     = new PaillierMath(targetKeys);
        this.targetKeys = targetKeys;
    }

    // ── Factories ─────────────────────────────────────────────────────────

    /**
     * Rotates from the keys currently installed on this thread to {@code targetKeys}.
     * The calling thread must already have a Paillier context (see {@link BlindContext#init()}
     * or {@link BlindContext#loadKeys(String)}).
     */
    public static BlindRotation fromCurrent(PaillierKeyPair targetKeys) {
        Objects.requireNonNull(targetKeys, "targetKeys must not be null");
        return new BlindRotation(BlindContext.getPaillier().getKeyPair(), targetKeys);
    }

    /** Rotates between two explicit key generations, independent of the thread-local context. */
    public static BlindRotation paillier(PaillierKeyPair sourceKeys, PaillierKeyPair targetKeys) {
        Objects.requireNonNull(sourceKeys, "sourceKeys must not be null");
        Objects.requireNonNull(targetKeys, "targetKeys must not be null");
        return new BlindRotation(sourceKeys, targetKeys);
    }

    /** Not yet implemented — BFV rotation requires re-encrypting through two native contexts. */
    public static BlindRotation bfv(int polyModulusDegree) {
        throw new UnsupportedOperationException(unsupported(Scheme.BFV));
    }

    /** Not yet implemented — CKKS rotation requires re-encrypting through two native contexts. */
    public static BlindRotation ckks(int polyModulusDegree, double scale) {
        throw new UnsupportedOperationException(unsupported(Scheme.CKKS));
    }

    private static String unsupported(Scheme scheme) {
        return "Key rotation for Scheme." + scheme + " is not implemented yet; only PAILLIER is "
             + "supported. Rotate BFV/CKKS data by decrypting under the old FheContext and "
             + "re-encrypting under a new one — see docs/SECURITY-AND-LIMITATIONS.md.";
    }

    // ── Rotation ──────────────────────────────────────────────────────────

    /**
     * Re-encrypts one ciphertext under the target keys. The plaintext exists only for the
     * duration of this call. Safe to call concurrently.
     *
     * @throws UnsupportedOperationException if the ciphertext is not a Paillier ciphertext
     * @throws IllegalStateException if the session is closed
     */
    public Ciphertext rotate(Ciphertext ciphertext) {
        Objects.requireNonNull(ciphertext, "ciphertext must not be null");
        ensureOpen();
        if (ciphertext.scheme() != Scheme.PAILLIER) {
            throw new UnsupportedOperationException(unsupported(ciphertext.scheme()));
        }
        BigInteger plain = source.decrypt(ciphertext);
        Ciphertext fresh = target.encrypt(plain);
        rotated.incrementAndGet();
        return fresh;
    }

    /** Number of ciphertexts re-encrypted by this session so far. */
    public long rotatedCount() {
        return rotated.get();
    }

    /** The key pair this session rotates towards — export it once the batch has been verified. */
    public PaillierKeyPair targetKeys() {
        return targetKeys;
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────

    /**
     * Installs the target keys as the calling thread's Paillier context, so subsequent
     * encrypt/decrypt runs under the new generation. Call this only once the rotated values
     * have been persisted — afterwards, ciphertexts still under the old keys will no longer
     * decrypt on this thread.
     *
     * <p>Persist the new bundle with {@link BlindContext#exportKeys(String)} after committing.
     */
    @AIIdempotent(reason = "The second call observes committed == true and returns; installing the "
                         + "same keys twice must not be an error")
    public synchronized void commit() {
        ensureOpen();
        if (committed) {
            return;
        }
        BlindContext.init(targetKeys);
        committed = true;
    }

    /** True once {@link #commit()} has installed the target keys. */
    public boolean isCommitted() {
        return committed;
    }

    /**
     * Ends the session. An uncommitted session leaves the thread's context untouched, so
     * abandoning a rotation cannot strand the caller without a working key set. Already-rotated
     * values stay rotated — this rolls back nothing in your datastore.
     */
    @AIIdempotent(reason = "Guarded by the closed flag; repeated close() is a no-op and never "
                         + "disturbs the installed context")
    @Override
    public synchronized void close() {
        closed = true;
    }

    private void ensureOpen() {
        if (closed) {
            throw new IllegalStateException("BlindRotation session has been closed");
        }
    }
}

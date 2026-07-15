package se.deversity.blindbean.context;

import se.deversity.blindbean.annotations.Scheme;
import se.deversity.blindbean.core.Ciphertext;
import se.deversity.blindbean.fhe.FheCiphertextNative;
import se.deversity.blindbean.fhe.FheContext;
import se.deversity.blindbean.math.PaillierKeyPair;
import se.deversity.blindbean.math.PaillierMath;

import se.deversity.vibetags.annotations.AIIdempotent;
import se.deversity.vibetags.annotations.AIPrivacy;
import se.deversity.vibetags.annotations.AIPublicAPI;
import se.deversity.vibetags.annotations.AISecure;
import se.deversity.vibetags.annotations.AITestDriven;
import se.deversity.vibetags.annotations.AIThreadSafe;

import java.lang.foreign.MemorySegment;
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
 * side by side, so plaintext exists only inside {@link #rotate(Ciphertext)} and the thread-local
 * context is not disturbed until {@link #commit()}.
 *
 * <pre>{@code
 * PaillierKeyPair next = new PaillierKeyPair(2048);
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
 * <p>BFV and CKKS rotate the same way, through a second native context holding fresh keys:
 *
 * <pre>{@code
 * BlindContext.initBfv(8192);
 * try (BlindRotation rotation = BlindRotation.fromCurrentFhe()) {   // fresh SEAL keys, same params
 *     for (Reading r : repository.findAll()) {
 *         new ReadingBlindWrapper(r).rotateValue(rotation);
 *         repository.save(r);
 *     }
 *     rotation.commit();   // installs the new context and retires the old one
 * }
 * }</pre>
 *
 * <p>Rotation is <em>not</em> atomic across your datastore: {@link #rotate(Ciphertext)} hands
 * back a re-encrypted value, but persisting it is yours to do, and a crash midway leaves some
 * rows under the old keys and some under the new. Keep the old bundle until the batch has been
 * verified, and retire it only afterwards.
 *
 * <p><strong>Re-running an interrupted batch is safe.</strong> Every ciphertext is stamped with
 * the key generation that produced it ({@link se.deversity.blindbean.core.KeyTag}), so a row that already
 * moved is refused with a {@link se.deversity.blindbean.core.WrongKeyException} rather than rotated twice —
 * catch it and skip that row. This is worth spelling out because the failure it replaces was
 * invisible: neither Paillier nor SEAL rejects a foreign ciphertext, they decrypt it to a
 * plausible wrong value, so a second rotation used to overwrite good data with well-formed
 * garbage and nothing anywhere reported a problem.
 *
 * <p>Ciphertexts written before stamping existed carry no tag. They are still accepted (refusing
 * them would make existing data unreadable), and rotating one produces a stamped value — so a
 * dataset heals as it is rewritten, but an un-rewritten legacy row is not yet protected.
 *
 * <p>{@link #commit()} is terminal — rotating under retired keys after the application has moved
 * to the new ones is a bug, so it is refused rather than silently allowed.
 */
@AIPublicAPI
@AISecure(aspect = "key-rotation")
@AIPrivacy(reason = "Holds two generations of private key material — never log the key pairs, the "
                  + "native key payloads, the decrypted plaintext, or expose them in fixtures")
@AIThreadSafe(strategy = AIThreadSafe.Strategy.OTHER,
              note = "rotate() is concurrency-safe: PaillierMath is effectively immutable with a "
                   + "thread-safe SecureRandom, and each FheContext serializes its own native calls "
                   + "on nativeLock. The counter is an AtomicLong; commit()/close() are guarded by "
                   + "the session monitor and flip volatile flags that rotate() reads.")
@AITestDriven(coverageGoal = 90, testLocation = "src/test/java/se.deversity.blindbean/context")
public final class BlindRotation implements AutoCloseable {

    /** Re-encrypts one ciphertext and installs the target keys. One implementation per backend. */
    private sealed interface Engine permits PaillierEngine, FheEngine {
        Scheme scheme();
        Ciphertext rotate(Ciphertext ciphertext);
        /** Installs the target keys as the calling thread's context and retires the source. */
        void commit();
        /** Releases whatever the session created itself and did not hand over to BlindContext. */
        void release(boolean committed);
    }

    private final Engine engine;
    private final AtomicLong rotated = new AtomicLong();

    private volatile boolean closed = false;
    private volatile boolean committed = false;

    private BlindRotation(Engine engine) {
        this.engine = engine;
    }

    // ── Paillier ──────────────────────────────────────────────────────────

    /**
     * Rotates from the Paillier keys currently installed on this thread to {@code targetKeys}.
     * The calling thread must already have a Paillier context (see {@link BlindContext#init()}
     * or {@link BlindContext#loadKeys(String)}).
     */
    public static BlindRotation fromCurrent(PaillierKeyPair targetKeys) {
        Objects.requireNonNull(targetKeys, "targetKeys must not be null");
        return paillier(BlindContext.getPaillier().getKeyPair(), targetKeys);
    }

    /** Rotates between two explicit Paillier key generations, independent of the thread context. */
    public static BlindRotation paillier(PaillierKeyPair sourceKeys, PaillierKeyPair targetKeys) {
        Objects.requireNonNull(sourceKeys, "sourceKeys must not be null");
        Objects.requireNonNull(targetKeys, "targetKeys must not be null");
        if (sourceKeys.getN().equals(targetKeys.getN())) {
            throw new IllegalArgumentException(sameKeys("Paillier modulus"));
        }
        return new BlindRotation(new PaillierEngine(new PaillierMath(sourceKeys),
                                                    new PaillierMath(targetKeys),
                                                    targetKeys));
    }

    // ── BFV / CKKS ────────────────────────────────────────────────────────

    /**
     * Rotates from the FHE context currently installed on this thread onto a fresh context with
     * the same scheme and parameters but newly generated SEAL keys.
     *
     * <p>The session owns the context it creates: if the batch is abandoned, {@link #close()}
     * frees it; if it is committed, ownership passes to {@link BlindContext} and the retired
     * context is closed for you.
     */
    public static BlindRotation fromCurrentFhe() {
        FheContext source = BlindContext.getFheContext();
        FheContext target = switch (source.scheme()) {
            case BFV  -> FheContext.bfv(source.polyModulusDegree());
            case CKKS -> FheContext.ckks(source.polyModulusDegree(), source.scale());
            case PAILLIER -> throw new IllegalStateException(
                "The installed context is Paillier, not an FHE scheme — use fromCurrent(PaillierKeyPair).");
        };
        return new BlindRotation(new FheEngine(source, target, true, true));
    }

    /**
     * Rotates between two explicit FHE contexts. Both must use the same scheme and parameters,
     * and neither is closed by the session — their lifecycle stays with the caller.
     */
    public static BlindRotation fhe(FheContext source, FheContext target) {
        Objects.requireNonNull(source, "source context must not be null");
        Objects.requireNonNull(target, "target context must not be null");
        if (source == target) {
            throw new IllegalArgumentException(sameKeys("FHE context"));
        }
        if (source.scheme() != target.scheme()) {
            throw new IllegalArgumentException(
                "Rotation source and target must use the same scheme, got "
                + source.scheme() + " and " + target.scheme());
        }
        if (source.polyModulusDegree() != target.polyModulusDegree()) {
            throw new IllegalArgumentException(
                "Rotation source and target must use the same polyModulusDegree, got "
                + source.polyModulusDegree() + " and " + target.polyModulusDegree()
                + "; a ciphertext cannot move between parameter sets.");
        }
        return new BlindRotation(new FheEngine(source, target, false, false));
    }

    private static String sameKeys(String what) {
        return "Rotation source and target are the same key (identical " + what + ") — rotating onto "
             + "the same keys re-encrypts nothing and would retire a bundle that is still in use. "
             + "Generate a fresh key set for the target.";
    }

    // ── Rotation ──────────────────────────────────────────────────────────

    /**
     * Re-encrypts one ciphertext under the target keys. The plaintext exists only for the
     * duration of this call. Safe to call concurrently.
     *
     * @throws IllegalArgumentException if the ciphertext belongs to a different scheme than this
     *         session rotates
     * @throws IllegalStateException if the session is closed or already committed
     */
    public Ciphertext rotate(Ciphertext ciphertext) {
        Objects.requireNonNull(ciphertext, "ciphertext must not be null");
        ensureRotatable();
        if (ciphertext.scheme() != engine.scheme()) {
            throw new IllegalArgumentException(
                "This session rotates " + engine.scheme() + " ciphertexts, got "
                + ciphertext.scheme() + ". Open a separate rotation per scheme.");
        }
        Ciphertext fresh = engine.rotate(ciphertext);
        rotated.incrementAndGet();
        return fresh;
    }

    /** The scheme this session rotates. */
    public Scheme scheme() {
        return engine.scheme();
    }

    /** Number of ciphertexts re-encrypted by this session so far. */
    public long rotatedCount() {
        return rotated.get();
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────

    /**
     * Installs the target keys as the calling thread's context and retires the source, so
     * subsequent encrypt/decrypt runs under the new generation. Call this only once the rotated
     * values have been persisted — afterwards, ciphertexts still under the old keys will no
     * longer decrypt on this thread.
     *
     * <p>Terminal: {@link #rotate(Ciphertext)} is refused after a commit. Persist the new bundle
     * with {@link BlindContext#exportKeys(String)} afterwards.
     */
    @AIIdempotent(reason = "The second call observes committed == true and returns; installing the "
                         + "same keys twice must not be an error, and the source is retired once")
    public synchronized void commit() {
        ensureOpen();
        if (committed) {
            return;
        }
        engine.commit();
        committed = true;
    }

    /** True once {@link #commit()} has installed the target keys. */
    public boolean isCommitted() {
        return committed;
    }

    /**
     * Ends the session. An uncommitted session leaves the thread's context untouched and frees
     * any context the session created itself, so abandoning a rotation cannot strand the caller
     * without a working key set or leak a native context. Already-rotated values stay rotated —
     * this rolls back nothing in your datastore.
     */
    @AIIdempotent(reason = "Guarded by the closed flag; repeated close() is a no-op and never "
                         + "disturbs the installed context or double-frees a native context")
    @Override
    public synchronized void close() {
        if (closed) {
            return;
        }
        closed = true;
        engine.release(committed);
    }

    private void ensureOpen() {
        if (closed) {
            throw new IllegalStateException("BlindRotation session has been closed");
        }
    }

    private void ensureRotatable() {
        ensureOpen();
        if (committed) {
            throw new IllegalStateException(
                "This rotation has been committed — the thread now runs on the target keys, so "
                + "rotating further ciphertexts under the retired keys is refused. Open a new "
                + "session if more data still needs rotating.");
        }
    }

    // ── Engines ───────────────────────────────────────────────────────────

    private record PaillierEngine(PaillierMath source, PaillierMath target, PaillierKeyPair targetKeys)
            implements Engine {

        @Override
        public Scheme scheme() {
            return Scheme.PAILLIER;
        }

        @Override
        public Ciphertext rotate(Ciphertext ciphertext) {
            BigInteger plain = source.decrypt(ciphertext);
            return target.encrypt(plain);
        }

        @Override
        public void commit() {
            BlindContext.init(targetKeys);
        }

        @Override
        public void release(boolean committed) {
            // Key material is garbage-collected; nothing native to free.
        }
    }

    /**
     * BFV/CKKS rotation: decrypt through the source context, re-encrypt through the target.
     *
     * <p>Both schemes go through the batch path in both directions. A ciphertext carries every slot
     * whether the caller encrypted one value or a whole array, so decrypting and re-encrypting the
     * full slot vector rotates single values and batches identically — {@code decryptLong} /
     * {@code decryptDouble} still read slot 0 of the result. CKKS used to rotate through the scalar
     * path, which discarded every slot but the first.
     */
    private static final class FheEngine implements Engine {

        private final FheContext source;
        private final FheContext target;
        private final boolean ownsSource;
        private final boolean ownsTarget;

        FheEngine(FheContext source, FheContext target, boolean ownsSource, boolean ownsTarget) {
            this.source     = source;
            this.target     = target;
            this.ownsSource = ownsSource;
            this.ownsTarget = ownsTarget;
        }

        @Override
        public Scheme scheme() {
            return source.scheme();
        }

        @Override
        public Ciphertext rotate(Ciphertext ciphertext) {
            try (FheCiphertextNative in = FheCiphertextNative.fromBlindCiphertext(source, ciphertext)) {
                MemorySegment fresh = switch (source.scheme()) {
                    case BFV  -> target.encryptLongArray(source.decryptLongArray(in.handle()));
                    // CKKS goes through the batch path in both directions now that the bridge has
                    // one. It previously rotated via encryptDouble/decryptDouble, which reads slot
                    // 0 — so rotating a CKKS vector silently discarded every other slot.
                    case CKKS -> target.encryptDoubleArray(source.decryptDoubleArray(in.handle()));
                    case PAILLIER -> throw new IllegalStateException("unreachable: FheEngine on PAILLIER");
                };
                try (FheCiphertextNative out = new FheCiphertextNative(fresh, target)) {
                    return out.toBlindCiphertext();
                }
            }
        }

        @Override
        public void commit() {
            // Hand the target to the thread-local context, then retire the source we took from it.
            BlindContext.restore(new BlindContext.Snapshot(null, target));
            if (ownsSource) {
                source.close();
            }
        }

        @Override
        public void release(boolean committed) {
            // On commit the target belongs to BlindContext, which closes it on clear().
            if (ownsTarget && !committed) {
                target.close();
            }
        }
    }
}

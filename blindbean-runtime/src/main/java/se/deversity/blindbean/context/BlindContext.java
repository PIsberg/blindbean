package se.deversity.blindbean.context;

import se.deversity.blindbean.fhe.FheContext;
import se.deversity.blindbean.fhe.FheException;
import se.deversity.blindbean.math.PaillierKeyPair;
import se.deversity.blindbean.math.PaillierMath;

import org.jspecify.annotations.Nullable;

import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.Logger.Level.INFO;
import static java.lang.System.Logger.Level.WARNING;

import se.deversity.vibetags.annotations.AIAudit;
import se.deversity.vibetags.annotations.AICore;
import se.deversity.vibetags.annotations.AIIdempotent;
import se.deversity.vibetags.annotations.AIInputSanitized;
import se.deversity.vibetags.annotations.AIPublicAPI;
import se.deversity.vibetags.annotations.AISecure;
import se.deversity.vibetags.annotations.AITestDriven;
import se.deversity.vibetags.annotations.AIThreadSafe;

/**
 * Thread-local context holder for all BlindBean cryptographic backends.
 * <p>
 * Manages separate contexts for Paillier (PHE) and SEAL-backed FHE schemes.
 * Must be initialized before any cryptographic operation. Supports both
 * manual lifecycle management and try-with-resources via {@link #clear()}.
 */
@AICore
@AIPublicAPI
@AIAudit(checkFor = {"Resource Leaks", "Thread Safety", "Context Closure failures"})
@AIThreadSafe(strategy = AIThreadSafe.Strategy.THREAD_LOCAL,
              note = "Paillier and FHE state isolated in ThreadLocal fields; snapshot()/restore() required to propagate across virtual-thread boundaries")
@AISecure(aspect = "key-management")
@AITestDriven(coverageGoal = 90, testLocation = "src/test/java/se.deversity.blindbean/context")
public class BlindContext {

    /**
     * Platform logging, so a consumer binds whatever backend it already uses and BlindBean adds no
     * logging dependency to anyone's compile path.
     *
     * <p>Nothing here logs key material, plaintext or ciphertext bytes at any level. That is not a
     * style preference: {@code KeyBundle.paillierKeyPair} and {@code KeyBundle.nativeFhePayload}
     * carry an {@code @AISecureLogging} OMIT policy, and {@code BlindRotation} and {@code KeyBundle}
     * are {@code @AIPrivacy}-guarded. What is logged is shape and lifecycle: scheme, modulus size,
     * counts, byte lengths, and the key tag, which is a public generation identifier derived from
     * the public modulus and truncated here to 4 bytes.
     */
    private static final System.Logger LOG = System.getLogger(BlindContext.class.getName());

    private static final ThreadLocal<PaillierMath> paillierInstance = new ThreadLocal<>();
    private static final ThreadLocal<FheContext>    fheInstance      = new ThreadLocal<>();

    // ── Paillier (unchanged from original API) ────────────────

    /**
     * Default Paillier modulus size, in bits.
     *
     * <p>Paillier's hardness is factoring {@code n = p*q}, so the modulus is sized like an RSA
     * one. The previous default of 1024 was a 1024-bit modulus — roughly 80-bit security, which
     * NIST disallowed after 2013 — and it was the value every example told users to adopt,
     * including when generating the <em>new</em> key during a rotation, which is very often done
     * precisely because the old one is no longer trusted. 2048 is the minimum that still
     * qualifies; raise it to 3072 if you want to claim the 128-bit equivalence the BFV/CKKS
     * parameters carry.
     *
     * <p>{@code PaillierKeyPair} splits this across the two primes, so this is the size of
     * {@code n}, not of {@code p}.
     */
    public static final int DEFAULT_PAILLIER_BITS = 2048;

    public static void init() {
        long startNanos = System.nanoTime();
        LOG.log(DEBUG, "No key pair supplied; generating a {0}-bit Paillier modulus", DEFAULT_PAILLIER_BITS);

        PaillierMath math = new PaillierMath(new PaillierKeyPair(DEFAULT_PAILLIER_BITS));
        paillierInstance.set(math);

        LOG.log(INFO, "Paillier context ready: {0}-bit modulus, keyTag={1}, keygen took {2} ms",
            DEFAULT_PAILLIER_BITS, tagOf(math), millisSince(startNanos));
    }

    public static void init(PaillierKeyPair keyPair) {
        PaillierMath math = new PaillierMath(keyPair);
        paillierInstance.set(math);

        LOG.log(INFO, "Paillier context ready: caller-supplied key pair, keyTag={0}", tagOf(math));
    }

    public static PaillierMath getPaillier() {
        PaillierMath instance = paillierInstance.get();
        if (instance == null) {
            LOG.log(DEBUG, "No Paillier context on thread {0}; initialising one implicitly",
                Thread.currentThread().getName());
            init();
            return paillierInstance.get();
        }
        return instance;
    }

    // ── FHE (BFV / CKKS via Microsoft SEAL) ───────────────────

    /**
     * Initializes a BFV FHE context for the calling thread.
     * @param polyModulusDegree polynomial modulus degree (e.g., 4096, 8192, 16384)
     */
    public static void initBfv(int polyModulusDegree) {
        closeExistingFhe();
        long startNanos = System.nanoTime();
        LOG.log(DEBUG, "Creating a BFV context, polyModulusDegree={0}", polyModulusDegree);

        fheInstance.set(FheContext.bfv(polyModulusDegree));

        LOG.log(INFO, "BFV context ready: polyModulusDegree={0}, setup took {1} ms",
            polyModulusDegree, millisSince(startNanos));
    }

    /**
     * Initializes a CKKS FHE context for the calling thread.
     * @param polyModulusDegree polynomial modulus degree
     * @param scale CKKS scale parameter (e.g., 2^40)
     */
    public static void initCkks(int polyModulusDegree, double scale) {
        closeExistingFhe();
        long startNanos = System.nanoTime();
        LOG.log(DEBUG, "Creating a CKKS context, polyModulusDegree={0}, scale={1}", polyModulusDegree, scale);

        fheInstance.set(FheContext.ckks(polyModulusDegree, scale));

        LOG.log(INFO, "CKKS context ready: polyModulusDegree={0}, scale={1}, setup took {2} ms",
            polyModulusDegree, scale, millisSince(startNanos));
    }

    /**
     * Returns the FHE context for the calling thread.
     * @throws FheException if no FHE context has been initialized
     */
    public static FheContext getFheContext() {
        FheContext instance = fheInstance.get();
        if (instance == null) {
            throw new FheException("No FHE context initialized. Call BlindContext.initBfv() or initCkks() first.");
        }
        return instance;
    }

    // ── Serialization & Key Management ────────────────────────
    
    /**
     * Exports the current combined Paillier and Microsoft SEAL encryption states to a file.
     * This secures the keys allowing the application to persist data over restarts.
     * @param filePath the destination binary path to stream the bundle to.
     */
    @AISecure(aspect = "key-serialization")
    public static void exportKeys(
            @AIInputSanitized({AIInputSanitized.SanitizerType.PATH_TRAVERSAL}) String filePath) {
        // Assemble the bundle *before* touching the destination: opening a FileOutputStream
        // truncates it, so validating (or serializing the native state) afterwards would
        // destroy a previously exported bundle on the way to throwing.
        PaillierKeyPair kp = paillierInstance.get() != null ? paillierInstance.get().getKeyPair() : null;
        FheContext ctx = fheInstance.get();

        if (ctx == null && kp == null) {
            throw new FheException("No open BlindContext elements available to export");
        }

        // A failure here (e.g. the native exportState) propagates as-is and leaves the
        // destination untouched, which is the whole point of building the bundle first.
        KeyBundle bundle = new KeyBundle(
                kp,
                ctx != null ? ctx.scheme() : null,
                ctx != null ? ctx.polyModulusDegree() : 0,
                ctx != null ? ctx.scale() : 0.0,
                ctx != null ? ctx.exportState() : null
        );

        try (java.io.ObjectOutputStream oos = new java.io.ObjectOutputStream(new java.io.FileOutputStream(filePath))) {
            oos.writeObject(bundle);

            // Sizes and scheme only. The payload and the key pair are OMIT-masked. The payload is
            // read into a local first: calling the nullable getter twice inside a ternary is the
            // shape SpotBugs flags as NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE, and it is right to.
            byte[] exportedState = bundle.getNativeFhePayload();
            LOG.log(INFO, "Key bundle exported to {0}: paillier={1}, fheScheme={2}, nativeState={3} bytes",
                filePath,
                kp != null ? "yes" : "no",
                ctx != null ? ctx.scheme() : "none",
                exportedState != null ? exportedState.length : 0);
        } catch (Exception e) {
            throw new FheException("Key export failed", e);
        }
    }

    /**
     * Deserialization allowlist for {@link #loadKeys(String)}: only the classes that a
     * legitimate {@link KeyBundle} graph can contain. Everything else is rejected before
     * instantiation, blocking deserialization-gadget attacks via tampered key files.
     */
    private static final java.io.ObjectInputFilter KEY_BUNDLE_FILTER =
            java.io.ObjectInputFilter.Config.createFilter(
                "se.deversity.blindbean.context.KeyBundle;"
                + "se.deversity.blindbean.math.PaillierKeyPair;"
                + "se.deversity.blindbean.annotations.Scheme;"
                + "java.lang.Enum;"
                + "java.lang.Number;"
                + "java.math.BigInteger;"
                + "maxdepth=10;!*");

    /**
     * Restores encryption context from a previously exported state file.
     * @param filePath the binary bundle path.
     */
    @AISecure(aspect = "key-deserialization")
    public static void loadKeys(
            @AIInputSanitized({AIInputSanitized.SanitizerType.PATH_TRAVERSAL}) String filePath) {
        try (java.io.ObjectInputStream ois = new java.io.ObjectInputStream(new java.io.FileInputStream(filePath))) {
            ois.setObjectInputFilter(KEY_BUNDLE_FILTER);
            KeyBundle bundle = (KeyBundle) ois.readObject();
            LOG.log(DEBUG, "Key bundle read from {0}; deserialization filter accepted the graph", filePath);

            // Paillier resumption
            PaillierKeyPair paillierKeyPair = bundle.getPaillierKeyPair();
            byte[] restoredState = bundle.getNativeFhePayload();
            if (paillierKeyPair != null) {
                init(paillierKeyPair);
            }

            // FHE resumption
            se.deversity.blindbean.annotations.Scheme fheScheme = bundle.getFheScheme();
            byte[] nativeFhePayload = restoredState;
            if (fheScheme != null && nativeFhePayload != null) {
                if (fheScheme == se.deversity.blindbean.annotations.Scheme.BFV) {
                    initBfv(bundle.getPolyModulusDegree());
                } else if (fheScheme == se.deversity.blindbean.annotations.Scheme.CKKS) {
                    initCkks(bundle.getPolyModulusDegree(), bundle.getScale());
                }

                // Mount native pointers strictly; on failure close the freshly created
                // context rather than leaving one installed with non-imported default keys
                try {
                    fheInstance.get().importState(nativeFhePayload);
                    LOG.log(DEBUG, "Native {0} state imported: {1} bytes",
                        fheScheme, nativeFhePayload.length);
                } catch (RuntimeException e) {
                    LOG.log(WARNING, "Native key import failed for {0}; closing the half-built {1} context "
                        + "rather than leaving one installed with non-imported default keys", filePath, fheScheme);
                    closeExistingFhe();
                    throw e;
                }
            }

            // Outside the FHE branch on purpose. This INFO used to sit inside it, so loading a
            // Paillier-only bundle logged the export but never the load: the log showed keys
            // leaving the process and never coming back. Restoring keys is a main event whichever
            // backends the bundle carries.
            LOG.log(INFO, "Key bundle loaded from {0}: paillier={1}, fheScheme={2}, nativeState={3} bytes",
                filePath,
                paillierKeyPair != null ? "yes" : "no",
                fheScheme != null ? fheScheme : "none",
                restoredState != null ? restoredState.length : 0);
        } catch (FheException e) {
            throw e;
        } catch (Exception e) {
            throw new FheException("Key import failed", e);
        }
    }

    // ── Lifecycle ─────────────────────────────────────────────

    /**
     * Clears all thread-local state, releasing Paillier keys and
     * closing the native FHE context if present.
     */
    @AIIdempotent(reason = "ThreadLocal.remove() and FheContext.close() are both safe to call when no state is present")
    public static void clear() {
        LOG.log(DEBUG, "Clearing all BlindBean state held by thread {0}", Thread.currentThread().getName());
        paillierInstance.remove();
        closeExistingFhe();
    }

    /**
     * The first 4 bytes of the key tag, as hex.
     *
     * <p>The tag is a public generation identifier, derived from the public modulus, so it carries
     * no secret. It is truncated anyway: 4 bytes is enough to tell two generations apart in a log
     * while staying useless as a fingerprint of anything else.
     */
    private static String tagOf(PaillierMath math) {
        byte[] tag = math.keyTag();
        StringBuilder sb = new StringBuilder(8);
        for (int i = 0; i < Math.min(4, tag.length); i++) {
            sb.append(String.format("%02x", tag[i]));
        }
        return sb.toString();
    }

    private static long millisSince(long startNanos) {
        return (System.nanoTime() - startNanos) / 1_000_000L;
    }

    private static void closeExistingFhe() {
        FheContext existing = fheInstance.get();
        if (existing != null) {
            LOG.log(DEBUG, "Closing the {0} context held by thread {1}",
                existing.scheme(), Thread.currentThread().getName());
            existing.close();
            fheInstance.remove();
        }
    }

    // ── Async support — snapshot / restore ────────────────────────────────

    /**
     * Captures the calling thread's Paillier and FHE context references.
     * Used by {@code BlindAsync} to propagate context across virtual-thread boundaries.
     */
    public record Snapshot(@Nullable PaillierMath paillier, @Nullable FheContext fhe) {}

    /**
     * Returns a snapshot of the current thread's cryptographic context.
     * Both fields may be {@code null} if not initialized on this thread.
     */
    public static Snapshot snapshot() {
        Snapshot snapshot = new Snapshot(paillierInstance.get(), fheInstance.get());
        FheContext capturedFhe = snapshot.fhe();
        LOG.log(DEBUG, "Snapshot taken on thread {0}: paillier={1}, fhe={2}",
            Thread.currentThread().getName(),
            snapshot.paillier() != null,
            capturedFhe != null ? capturedFhe.scheme() : "none");
        return snapshot;
    }

    /**
     * Installs a previously captured snapshot on the current thread.
     * Does not close or replace any existing FHE context on this thread —
     * call {@link #clear()} first if that is needed.
     */
    public static void restore(Snapshot snapshot) {
        FheContext incomingFhe = snapshot.fhe();
        LOG.log(DEBUG, "Restoring snapshot onto thread {0}: paillier={1}, fhe={2}",
            Thread.currentThread().getName(),
            snapshot.paillier() != null,
            incomingFhe != null ? incomingFhe.scheme() : "none");
        if (snapshot.paillier() != null) {
            paillierInstance.set(snapshot.paillier());
        }
        if (snapshot.fhe() != null) {
            fheInstance.set(snapshot.fhe());
        }
    }
}

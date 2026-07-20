package se.deversity.blindbean.context;

import se.deversity.blindbean.fhe.FheContext;
import se.deversity.blindbean.fhe.FheException;
import se.deversity.blindbean.math.PaillierKeyPair;
import se.deversity.blindbean.math.PaillierMath;

import org.jspecify.annotations.Nullable;

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
        PaillierKeyPair kp = new PaillierKeyPair(DEFAULT_PAILLIER_BITS);
        paillierInstance.set(new PaillierMath(kp));
    }

    public static void init(PaillierKeyPair keyPair) {
        paillierInstance.set(new PaillierMath(keyPair));
    }

    public static PaillierMath getPaillier() {
        PaillierMath instance = paillierInstance.get();
        if (instance == null) {
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
        fheInstance.set(FheContext.bfv(polyModulusDegree));
    }

    /**
     * Initializes a CKKS FHE context for the calling thread.
     * @param polyModulusDegree polynomial modulus degree
     * @param scale CKKS scale parameter (e.g., 2^40)
     */
    public static void initCkks(int polyModulusDegree, double scale) {
        closeExistingFhe();
        fheInstance.set(FheContext.ckks(polyModulusDegree, scale));
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

            // Paillier resumption
            PaillierKeyPair paillierKeyPair = bundle.getPaillierKeyPair();
            if (paillierKeyPair != null) {
                init(paillierKeyPair);
            }

            // FHE resumption
            se.deversity.blindbean.annotations.Scheme fheScheme = bundle.getFheScheme();
            byte[] nativeFhePayload = bundle.getNativeFhePayload();
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
                } catch (RuntimeException e) {
                    closeExistingFhe();
                    throw e;
                }
            }
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
        paillierInstance.remove();
        closeExistingFhe();
    }

    private static void closeExistingFhe() {
        FheContext existing = fheInstance.get();
        if (existing != null) {
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
        return new Snapshot(paillierInstance.get(), fheInstance.get());
    }

    /**
     * Installs a previously captured snapshot on the current thread.
     * Does not close or replace any existing FHE context on this thread —
     * call {@link #clear()} first if that is needed.
     */
    public static void restore(Snapshot snapshot) {
        if (snapshot.paillier() != null) {
            paillierInstance.set(snapshot.paillier());
        }
        if (snapshot.fhe() != null) {
            fheInstance.set(snapshot.fhe());
        }
    }
}

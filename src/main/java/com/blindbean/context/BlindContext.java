package com.blindbean.context;

import com.blindbean.fhe.FheContext;
import com.blindbean.fhe.FheException;
import com.blindbean.math.PaillierKeyPair;
import com.blindbean.math.PaillierMath;

import se.deversity.vibetags.annotations.AIAudit;
import se.deversity.vibetags.annotations.AICore;

/**
 * Thread-local context holder for all BlindBean cryptographic backends.
 * <p>
 * Manages separate contexts for Paillier (PHE) and SEAL-backed FHE schemes.
 * Must be initialized before any cryptographic operation. Supports both
 * manual lifecycle management and try-with-resources via {@link #clear()}.
 */
@AICore
@AIAudit(checkFor = {"Resource Leaks", "Thread Safety", "Context Closure failures"})
public class BlindContext {
    private static final ThreadLocal<PaillierMath> paillierInstance = new ThreadLocal<>();
    private static final ThreadLocal<FheContext>    fheInstance      = new ThreadLocal<>();

    // ── Paillier (unchanged from original API) ────────────────

    public static void init() {
        PaillierKeyPair kp = new PaillierKeyPair(1024); // smaller key size for prototype performance
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
    public static void exportKeys(String filePath) {
        try (java.io.ObjectOutputStream oos = new java.io.ObjectOutputStream(new java.io.FileOutputStream(filePath))) {
            PaillierKeyPair kp = paillierInstance.get() != null ? paillierInstance.get().getKeyPair() : null;
            FheContext ctx = fheInstance.get();
            
            if (ctx == null && kp == null) {
                throw new FheException("No open BlindContext elements available to export");
            }
            
            KeyBundle bundle = new KeyBundle(
                    kp,
                    ctx != null ? ctx.scheme() : null,
                    ctx != null ? ctx.polyModulusDegree() : 0,
                    ctx != null ? ctx.scale() : 0.0,
                    ctx != null ? ctx.exportState() : null
            );
            oos.writeObject(bundle);
        } catch (Exception e) {
            throw new FheException("Key export failed", e);
        }
    }

    /**
     * Restores encryption context from a previously exported state file.
     * @param filePath the binary bundle path.
     */
    public static void loadKeys(String filePath) {
        try (java.io.ObjectInputStream ois = new java.io.ObjectInputStream(new java.io.FileInputStream(filePath))) {
            KeyBundle bundle = (KeyBundle) ois.readObject();
            
            // Paillier resumption
            if (bundle.getPaillierKeyPair() != null) {
                init(bundle.getPaillierKeyPair());
            }

            // FHE resumption
            if (bundle.getFheScheme() != null && bundle.getNativeFhePayload() != null) {
                if (bundle.getFheScheme() == com.blindbean.annotations.Scheme.BFV) {
                    initBfv(bundle.getPolyModulusDegree());
                } else if (bundle.getFheScheme() == com.blindbean.annotations.Scheme.CKKS) {
                    initCkks(bundle.getPolyModulusDegree(), bundle.getScale());
                }
                
                // Mount native pointers strictly
                fheInstance.get().importState(bundle.getNativeFhePayload());
            }
        } catch (Exception e) {
            throw new FheException("Key import failed", e);
        }
    }

    // ── Lifecycle ─────────────────────────────────────────────

    /**
     * Clears all thread-local state, releasing Paillier keys and
     * closing the native FHE context if present.
     */
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
    public record Snapshot(PaillierMath paillier, FheContext fhe) {}

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

package com.blindbean.context;

import com.blindbean.fhe.FheContext;
import com.blindbean.fhe.FheException;
import com.blindbean.math.PaillierKeyPair;
import com.blindbean.math.PaillierMath;

/**
 * Thread-local context holder for all BlindBean cryptographic backends.
 * <p>
 * Manages separate contexts for Paillier (PHE) and SEAL-backed FHE schemes.
 * Must be initialized before any cryptographic operation. Supports both
 * manual lifecycle management and try-with-resources via {@link #clear()}.
 */
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
}

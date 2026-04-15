package com.blindbean.fhe;

import com.blindbean.annotations.Scheme;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

/**
 * High-level AutoCloseable wrapper around a native FHE context.
 * Enables try-with-resources usage for deterministic cleanup of SEAL resources.
 *
 * <pre>{@code
 * try (var ctx = FheContext.bfv(8192)) {
 *     FheCiphertextNative ct = ctx.encryptLong(42L);
 *     // ... operations ...
 * }
 * }</pre>
 */
public class FheContext implements AutoCloseable {

    private final MemorySegment handle;
    private final Scheme scheme;
    private final Arena arena;
    private final int polyModulusDegree;
    private final double scale;
    private volatile boolean closed = false;

    private FheContext(MemorySegment handle, Scheme scheme, Arena arena, int polyModulusDegree, double scale) {
        if (handle.equals(MemorySegment.NULL)) {
            throw new FheException("Failed to initialize FHE context — native call returned NULL");
        }
        this.handle = handle;
        this.scheme = scheme;
        this.arena  = arena;
        this.polyModulusDegree = polyModulusDegree;
        this.scale = scale;
    }

    /** Creates a BFV context with the given polynomial modulus degree. */
    public static FheContext bfv(int polyModulusDegree) {
        Arena arena = Arena.ofShared();
        MemorySegment h = FheNativeBridge.fhe_init_bfv(polyModulusDegree);
        return new FheContext(h, Scheme.BFV, arena, polyModulusDegree, 0.0);
    }

    /** Creates a CKKS context with the given polynomial modulus degree and scale. */
    public static FheContext ckks(int polyModulusDegree, double scale) {
        Arena arena = Arena.ofShared();
        MemorySegment h = FheNativeBridge.fhe_init_ckks(polyModulusDegree, scale);
        return new FheContext(h, Scheme.CKKS, arena, polyModulusDegree, scale);
    }

    public int polyModulusDegree() { return polyModulusDegree; }
    public double scale() { return scale; }

    /** Returns the raw native handle for use with {@link FheNativeBridge}. */
    public MemorySegment handle() {
        ensureOpen();
        return handle;
    }

    /** Returns the encryption scheme of this context. */
    public Scheme scheme() {
        return scheme;
    }

    /** Encrypts a long value (BFV contexts only). */
    public MemorySegment encryptLong(long value) {
        ensureOpen();
        if (scheme != Scheme.BFV) {
            throw new FheException("encryptLong requires BFV context, got " + scheme);
        }
        MemorySegment ct = FheNativeBridge.fhe_encrypt_long(handle, value);
        if (ct.equals(MemorySegment.NULL)) {
            throw new FheException("fhe_encrypt_long returned NULL");
        }
        return ct;
    }

    /** Decrypts a ciphertext to a long value (BFV contexts only). */
    public long decryptLong(MemorySegment ct) {
        ensureOpen();
        if (scheme != Scheme.BFV) {
            throw new FheException("decryptLong requires BFV context, got " + scheme);
        }
        return FheNativeBridge.fhe_decrypt_long(handle, ct);
    }

    /** Encrypts a long[] block directly into a single SIMD BFV Batch Ciphertext. */
    public MemorySegment encryptLongArray(long[] values) {
        ensureOpen();
        if (scheme != Scheme.BFV) {
            throw new FheException("encryptLongArray requires BFV context, got " + scheme);
        }
        try (java.lang.foreign.Arena arena = java.lang.foreign.Arena.ofConfined()) {
            java.lang.foreign.MemorySegment arrayBuffer = arena.allocateFrom(java.lang.foreign.ValueLayout.JAVA_LONG, values);
            MemorySegment ct = FheNativeBridge.fhe_encrypt_long_array(handle, arrayBuffer, values.length);
            if (ct.equals(MemorySegment.NULL)) {
                throw new FheException("fhe_encrypt_long_array returned NULL. Matrix may be too large.");
            }
            return ct;
        }
    }

    /** Decrypts a single SIMD BFV Batch Ciphertext into a long[] block. */
    public long[] decryptLongArray(MemorySegment ct) {
        ensureOpen();
        if (scheme != Scheme.BFV) {
            throw new FheException("decryptLongArray requires BFV context, got " + scheme);
        }
        try (java.lang.foreign.Arena arena = java.lang.foreign.Arena.ofConfined()) {
            java.lang.foreign.MemorySegment outBuffer = arena.allocate(java.lang.foreign.ValueLayout.JAVA_LONG, 8192);
            int count = FheNativeBridge.fhe_decrypt_long_array(handle, ct, outBuffer, 8192);
            if (count == 0) return new long[0];
            return outBuffer.asSlice(0, count * 8L).toArray(java.lang.foreign.ValueLayout.JAVA_LONG);
        }
    }

    /** Encrypts a double value (CKKS contexts only). */
    public MemorySegment encryptDouble(double value) {
        ensureOpen();
        if (scheme != Scheme.CKKS) {
            throw new FheException("encryptDouble requires CKKS context, got " + scheme);
        }
        MemorySegment ct = FheNativeBridge.fhe_encrypt_double(handle, value);
        if (ct.equals(MemorySegment.NULL)) {
            throw new FheException("fhe_encrypt_double returned NULL");
        }
        return ct;
    }

    /** Decrypts a ciphertext to a double value (CKKS contexts only). */
    public double decryptDouble(MemorySegment ct) {
        ensureOpen();
        if (scheme != Scheme.CKKS) {
            throw new FheException("decryptDouble requires CKKS context, got " + scheme);
        }
        return FheNativeBridge.fhe_decrypt_double(handle, ct);
    }

    /** Exports the underlying SEAL keys natively. */
    public byte[] exportState() {
        ensureOpen();
        try (java.lang.foreign.Arena a = java.lang.foreign.Arena.ofConfined()) {
            java.lang.foreign.MemorySegment lenSeg = a.allocate(java.lang.foreign.ValueLayout.JAVA_LONG);
            lenSeg.set(java.lang.foreign.ValueLayout.JAVA_LONG, 0, 0L);

            FheNativeBridge.fhe_export_keys(handle, java.lang.foreign.MemorySegment.NULL, lenSeg);
            long requiredSize = lenSeg.get(java.lang.foreign.ValueLayout.JAVA_LONG, 0);

            if (requiredSize <= 0) {
                throw new FheException("Failed to query serialization size for key export");
            }

            java.lang.foreign.MemorySegment buf = a.allocate(requiredSize);
            lenSeg.set(java.lang.foreign.ValueLayout.JAVA_LONG, 0, requiredSize);

            int rc = FheNativeBridge.fhe_export_keys(handle, buf, lenSeg);
            if (rc != 0) {
                throw new FheException("Key export failed", rc);
            }

            long actualLen = lenSeg.get(java.lang.foreign.ValueLayout.JAVA_LONG, 0);
            return buf.asSlice(0, actualLen).toArray(java.lang.foreign.ValueLayout.JAVA_BYTE);
        }
    }

    /** Reloads the underlying SEAL keys natively. */
    public void importState(byte[] data) {
        ensureOpen();
        try (java.lang.foreign.Arena a = java.lang.foreign.Arena.ofConfined()) {
            java.lang.foreign.MemorySegment buf = a.allocateFrom(java.lang.foreign.ValueLayout.JAVA_BYTE, data);
            int rc = FheNativeBridge.fhe_import_keys(handle, buf, data.length);
            if (rc != 0) {
                throw new FheException("Key import failed", rc);
            }
        }
    }

    /** Homomorphic addition of two ciphertexts. */
    public MemorySegment add(MemorySegment a, MemorySegment b) {
        ensureOpen();
        MemorySegment result = FheNativeBridge.fhe_add(handle, a, b);
        if (result.equals(MemorySegment.NULL)) {
            throw new FheException("fhe_add returned NULL");
        }
        return result;
    }

    /** Homomorphic subtraction of two ciphertexts. */
    public MemorySegment subtract(MemorySegment a, MemorySegment b) {
        ensureOpen();
        MemorySegment result = FheNativeBridge.fhe_subtract(handle, a, b);
        if (result.equals(MemorySegment.NULL)) {
            throw new FheException("fhe_subtract returned NULL");
        }
        return result;
    }

    /** Homomorphic multiplication of two ciphertexts (auto-relinearized). */
    public MemorySegment multiply(MemorySegment a, MemorySegment b) {
        ensureOpen();
        MemorySegment result = FheNativeBridge.fhe_multiply(handle, a, b);
        if (result.equals(MemorySegment.NULL)) {
            throw new FheException("fhe_multiply returned NULL");
        }
        return result;
    }

    /** Returns the remaining noise budget in bits (BFV only; returns -1 for CKKS). */
    public int noiseBudget(MemorySegment ct) {
        ensureOpen();
        return FheNativeBridge.fhe_noise_budget(handle, ct);
    }

    /** Frees a ciphertext handle. */
    public void freeCiphertext(MemorySegment ct) {
        FheNativeBridge.fhe_free_ciphertext(ct);
    }

    private void ensureOpen() {
        if (closed) {
            throw new FheException("FheContext has been closed");
        }
    }

    @Override
    public void close() {
        if (!closed) {
            closed = true;
            FheNativeBridge.fhe_destroy_context(handle);
            arena.close();
        }
    }
}

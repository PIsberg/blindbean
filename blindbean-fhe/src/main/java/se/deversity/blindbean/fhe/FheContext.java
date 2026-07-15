package se.deversity.blindbean.fhe;

import se.deversity.blindbean.annotations.Scheme;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

import se.deversity.vibetags.annotations.AIContext;
import se.deversity.vibetags.annotations.AIContract;
import se.deversity.vibetags.annotations.AICore;
import se.deversity.vibetags.annotations.AIIdempotent;
import se.deversity.vibetags.annotations.AIStrictExceptions;
import se.deversity.vibetags.annotations.AIObservability;
import se.deversity.vibetags.annotations.AIPerformance;
import se.deversity.vibetags.annotations.AISecure;
import se.deversity.vibetags.annotations.AITestDriven;
import se.deversity.vibetags.annotations.AIThreadSafe;

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
@AICore
@AIContract(reason = "Public FHE API consumed by generated BlindWrapper classes; any signature change requires processor regeneration and a major version bump")
@AIThreadSafe(strategy = AIThreadSafe.Strategy.SYNCHRONIZED,
              note = "All native FFM operations are guarded by nativeLock to prevent concurrent SEAL context access")
@AISecure(aspect = "fhe-encryption")
@AITestDriven(coverageGoal = 90, testLocation = "src/test/java/se.deversity.blindbean/fhe")
public class FheContext implements AutoCloseable {

    private final MemorySegment handle;
    private final Scheme scheme;
    private final Arena arena;
    private final int polyModulusDegree;
    private final double scale;
    private volatile boolean closed = false;
    private final Object nativeLock = new Object();

    /**
     * Fingerprint of the SEAL keys currently held, stamped into every ciphertext this context
     * serializes and checked on every one it reads back ({@link se.deversity.blindbean.core.KeyTag}).
     *
     * <p>Derived from the serialized key blob rather than randomly assigned, because it has to
     * survive an {@code exportState()} / {@code importState()} round trip: a random id would be
     * regenerated on restart and the context would then reject its own ciphertexts. Computed
     * lazily — the derivation serializes every key, which is far too expensive to do in the
     * constructor of a context that may never serialize a ciphertext — and cleared by
     * {@link #importState(byte[])}, which replaces the keys underneath it.
     */
    private volatile byte[] keyTag;

    /** BFV plaintext modulus, fetched once. -1 = not yet asked. */
    private volatile long plainModulus = -1;

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
        MemorySegment h = initNative(() -> FheNativeBridge.fhe_init_bfv(polyModulusDegree));
        return create(h, Scheme.BFV, polyModulusDegree, 0.0);
    }

    /** Creates a CKKS context with the given polynomial modulus degree and scale. */
    public static FheContext ckks(int polyModulusDegree, double scale) {
        MemorySegment h = initNative(() -> FheNativeBridge.fhe_init_ckks(polyModulusDegree, scale));
        return create(h, Scheme.CKKS, polyModulusDegree, scale);
    }

    /**
     * Wraps a freshly initialized native handle. The arena is opened only once the native
     * call has succeeded, and is closed again if construction still fails (NULL handle), so
     * a rejected context — an unloadable library, or parameters SEAL refuses — cannot leak
     * a shared arena on every attempt.
     */
    private static FheContext create(MemorySegment handle, Scheme scheme, int polyModulusDegree, double scale) {
        Arena arena = Arena.ofShared();
        try {
            return new FheContext(handle, scheme, arena, polyModulusDegree, scale);
        } catch (RuntimeException e) {
            arena.close();
            throw e;
        }
    }

    /**
     * Runs a native context initializer, converting linkage failures (missing
     * or unloadable native library) into an {@link FheException} carrying the
     * guided fix-it message from {@link #nativeLoadGuidance(Throwable)}.
     */
    @AIContext(focus = "Every native context entry point must be routed through this helper so the missing-library failure — the first error most new users hit — stays actionable",
               avoids = "Calling FheNativeBridge init symbols directly from a factory, which would surface a bare UnsatisfiedLinkError with no remediation guidance")
    @AIStrictExceptions(reason = "Only linkage errors may be translated here; a genuine SEAL failure must not be disguised as a missing-library problem")
    static MemorySegment initNative(java.util.function.Supplier<MemorySegment> init) {
        try {
            return init.get();
        } catch (UnsatisfiedLinkError | ExceptionInInitializerError | NoClassDefFoundError e) {
            throw new FheException(nativeLoadGuidance(e), e);
        }
    }

    /**
     * Builds an actionable message for the very first failure a new user is
     * likely to hit: the native SEAL bridge could not be loaded. Explains what
     * was searched and exactly how to fix it, instead of a bare linkage error.
     */
    static String nativeLoadGuidance(Throwable cause) {
        String configured = System.getProperty("blindbean.native.path");
        String os = System.getProperty("os.name", "unknown");
        String arch = System.getProperty("os.arch", "unknown");
        StringBuilder sb = new StringBuilder(512);
        sb.append("BlindBean could not load the native FHE library (blindbean_fhe).\n");
        sb.append("  OS/arch: ").append(os).append('/').append(arch).append('\n');
        if (configured == null || configured.isBlank()) {
            sb.append("  The system property 'blindbean.native.path' is NOT set.\n");
            sb.append("  Fix: pass -Dblindbean.native.path=<dir containing the built library>\n");
        } else {
            sb.append("  Searched 'blindbean.native.path' = ").append(configured).append('\n');
            sb.append("  Fix: verify the library exists there for this OS/arch");
            if (os.toLowerCase(java.util.Locale.ROOT).contains("win")) {
                sb.append(" (MSVC builds place it under a Release/ subdirectory)");
            }
            sb.append(".\n");
        }
        sb.append("  Build it once with: cmake -S blindbean-fhe/src/main/native -B build-native "
                + "-DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake && "
                + "cmake --build build-native --config Release\n");
        sb.append("  Docs: README.md 'Prerequisites' and CLAUDE.md 'Build & Test'.");
        if (cause != null && cause.getMessage() != null) {
            sb.append("\n  Underlying error: ").append(cause.getMessage());
        }
        return sb.toString();
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
        synchronized (nativeLock) {
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
    }

    /** Decrypts a ciphertext to a long value (BFV contexts only). */
    public long decryptLong(MemorySegment ct) {
        synchronized (nativeLock) {
            ensureOpen();
            if (scheme != Scheme.BFV) {
                throw new FheException("decryptLong requires BFV context, got " + scheme);
            }
            requireDecryptable(ct);
            return FheNativeBridge.fhe_decrypt_long(handle, ct);
        }
    }

    /**
     * BFV plaintext modulus {@code t}. Every slot is a value mod {@code t}; 0 for CKKS, which has
     * no plaintext modulus. Cached — it is fixed for the life of the context.
     */
    public long plainModulus() {
        long t = plainModulus;
        if (t == -1) {
            synchronized (nativeLock) {
                ensureOpen();
                t = FheNativeBridge.fhe_plain_modulus(handle);
                plainModulus = t;
            }
        }
        return t;
    }

    /** Batching slots available: {@code polyModulusDegree} for BFV, half that for CKKS. */
    public long slotCount() {
        synchronized (nativeLock) {
            ensureOpen();
            return FheNativeBridge.fhe_slot_count(handle);
        }
    }

    /**
     * Largest magnitude a BFV slot can carry, i.e. {@code (t-1)/2}. Values outside
     * {@code [-maxSlotValue, +maxSlotValue]} cannot be represented.
     */
    public long maxSlotValue() {
        return (plainModulus() - 1) / 2;
    }

    /**
     * Rejects values a BFV slot cannot hold.
     *
     * <p>This exists because SEAL does not. {@code BatchEncoder::encode} reduces an out-of-range
     * value mod {@code t} without complaint, so a {@code long[]} carrying real longs came back as
     * plausible nonsense — 1,000,000 decrypted to -32,193 — with no exception and no noise-budget
     * warning. Worse, a single out-of-range entry corrupted <em>every other slot in the vector</em>,
     * not just its own. The default parameters give a 20-bit {@code t}, so the usable range is only
     * about ±516,000: a "long" array is really a 20-bit int array, and silently lying about it is
     * the worst of the available options.
     */
    private void requireEncodable(long[] values) {
        long max = maxSlotValue();
        for (int i = 0; i < values.length; i++) {
            if (values[i] > max || values[i] < -max) {
                throw new FheException(
                    "BFV slot " + i + " holds " + values[i] + ", which this context cannot represent: "
                    + "the plaintext modulus is " + plainModulus() + ", so a slot carries only "
                    + "[-" + max + ", " + max + "]. SEAL would have reduced it mod t and returned a "
                    + "plausible wrong number instead of failing — and corrupted the other slots with "
                    + "it. Scale the value down, or raise the plaintext modulus.");
            }
        }
    }

    /** Encrypts a long[] block directly into a single SIMD BFV Batch Ciphertext. */
    @AIPerformance
    public MemorySegment encryptLongArray(long[] values) {
        synchronized (nativeLock) {
            ensureOpen();
            if (scheme != Scheme.BFV) {
                throw new FheException("encryptLongArray requires BFV context, got " + scheme);
            }
            requireEncodable(values);
            try (java.lang.foreign.Arena arena = java.lang.foreign.Arena.ofConfined()) {
                java.lang.foreign.MemorySegment arrayBuffer = arena.allocateFrom(java.lang.foreign.ValueLayout.JAVA_LONG, values);
                MemorySegment ct = FheNativeBridge.fhe_encrypt_long_array(handle, arrayBuffer, values.length);
                if (ct.equals(MemorySegment.NULL)) {
                    throw new FheException("fhe_encrypt_long_array returned NULL. Matrix may be too large.");
                }
                return ct;
            }
        }
    }

    /**
     * Encrypts a double[] into a single CKKS ciphertext, one value per slot.
     *
     * <p>CKKS is a vector scheme, but the bridge only ever exposed the scalar path — so every
     * ciphertext wasted all but one of its {@code degree/2} slots, and a CKKS key rotation could
     * only carry slot 0.
     */
    public MemorySegment encryptDoubleArray(double[] values) {
        synchronized (nativeLock) {
            ensureOpen();
            if (scheme != Scheme.CKKS) {
                throw new FheException("encryptDoubleArray requires CKKS context, got " + scheme);
            }
            try (java.lang.foreign.Arena arena = java.lang.foreign.Arena.ofConfined()) {
                java.lang.foreign.MemorySegment buf =
                        arena.allocateFrom(java.lang.foreign.ValueLayout.JAVA_DOUBLE, values);
                MemorySegment ct = FheNativeBridge.fhe_encrypt_double_array(handle, buf, values.length);
                if (ct.equals(MemorySegment.NULL)) {
                    throw new FheException(
                        "fhe_encrypt_double_array returned NULL — " + values.length
                        + " values against " + slotCount() + " slots.");
                }
                return ct;
            }
        }
    }

    /** Decrypts a CKKS ciphertext into its full slot vector. Approximate, as CKKS always is. */
    public double[] decryptDoubleArray(MemorySegment ct) {
        synchronized (nativeLock) {
            ensureOpen();
            if (scheme != Scheme.CKKS) {
                throw new FheException("decryptDoubleArray requires CKKS context, got " + scheme);
            }
            try (java.lang.foreign.Arena arena = java.lang.foreign.Arena.ofConfined()) {
                long slots = slotCount();
                java.lang.foreign.MemorySegment out =
                        arena.allocate(java.lang.foreign.ValueLayout.JAVA_DOUBLE, slots);
                int n = FheNativeBridge.fhe_decrypt_double_array(handle, ct, out, slots);
                if (n <= 0) {
                    throw new FheException("fhe_decrypt_double_array returned no slots");
                }
                double[] result = new double[n];
                java.lang.foreign.MemorySegment.copy(
                        out, java.lang.foreign.ValueLayout.JAVA_DOUBLE, 0, result, 0, n);
                return result;
            }
        }
    }

    /** Decrypts a single SIMD BFV Batch Ciphertext into a long[] block. */
    public long[] decryptLongArray(MemorySegment ct) {
        synchronized (nativeLock) {
            ensureOpen();
            if (scheme != Scheme.BFV) {
                throw new FheException("decryptLongArray requires BFV context, got " + scheme);
            }
            requireDecryptable(ct);
            try (java.lang.foreign.Arena arena = java.lang.foreign.Arena.ofConfined()) {
                // BFV batching exposes exactly polyModulusDegree slots; a fixed-size buffer
                // would silently drop the tail of the batch on larger contexts.
                long slots = polyModulusDegree;
                java.lang.foreign.MemorySegment outBuffer =
                        arena.allocate(java.lang.foreign.ValueLayout.JAVA_LONG, slots);
                int count = FheNativeBridge.fhe_decrypt_long_array(handle, ct, outBuffer, slots);
                if (count == 0) return new long[0];
                return outBuffer.asSlice(0, count * 8L).toArray(java.lang.foreign.ValueLayout.JAVA_LONG);
            }
        }
    }

    /** Encrypts a double value (CKKS contexts only). */
    public MemorySegment encryptDouble(double value) {
        synchronized (nativeLock) {
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
    }

    /** Decrypts a ciphertext to a double value (CKKS contexts only). */
    public double decryptDouble(MemorySegment ct) {
        synchronized (nativeLock) {
            ensureOpen();
            if (scheme != Scheme.CKKS) {
                throw new FheException("decryptDouble requires CKKS context, got " + scheme);
            }
            return FheNativeBridge.fhe_decrypt_double(handle, ct);
        }
    }

    /** Exports the underlying SEAL keys natively. */
    public byte[] exportState() {
        synchronized (nativeLock) {
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
    }

    /** Reloads the underlying SEAL keys natively. */
    public void importState(byte[] data) {
        synchronized (nativeLock) {
            ensureOpen();
            try (java.lang.foreign.Arena a = java.lang.foreign.Arena.ofConfined()) {
                java.lang.foreign.MemorySegment buf = a.allocateFrom(java.lang.foreign.ValueLayout.JAVA_BYTE, data);
                int rc = FheNativeBridge.fhe_import_keys(handle, buf, data.length);
                if (rc != 0) {
                    throw new FheException("Key import failed", rc);
                }
                // The keys just changed underneath the fingerprint; recompute it on next use, or
                // this context would keep stamping ciphertexts with the retired generation's tag.
                keyTag = null;
            }
        }
    }

    /**
     * Fingerprint of this context's key generation — a one-way digest of the serialized keys, not
     * key material. Stable across an export/import round trip, so a context that reloads a key
     * file still recognises the ciphertexts it wrote before the restart.
     */
    public byte[] keyTag() {
        byte[] tag = keyTag;
        if (tag == null) {
            synchronized (nativeLock) {
                tag = keyTag;
                if (tag == null) {
                    tag = se.deversity.blindbean.core.KeyTag.derive(exportState());
                    keyTag = tag;
                }
            }
        }
        return tag.clone();
    }

    /** Homomorphic addition of two ciphertexts. */
    public MemorySegment add(MemorySegment a, MemorySegment b) {
        synchronized (nativeLock) {
            ensureOpen();
            MemorySegment result = FheNativeBridge.fhe_add(handle, a, b);
            if (result.equals(MemorySegment.NULL)) {
                throw new FheException("fhe_add returned NULL");
            }
            return result;
        }
    }

    /** Homomorphic subtraction of two ciphertexts. */
    public MemorySegment subtract(MemorySegment a, MemorySegment b) {
        synchronized (nativeLock) {
            ensureOpen();
            MemorySegment result = FheNativeBridge.fhe_subtract(handle, a, b);
            if (result.equals(MemorySegment.NULL)) {
                throw new FheException("fhe_subtract returned NULL");
            }
            return result;
        }
    }

    /**
     * Homomorphic multiplication of two ciphertexts.
     * The result is automatically relinearized (both BFV and CKKS) to reduce ciphertext
     * size back to two components, and rescaled (CKKS only) to maintain the scale invariant.
     * Without relinearization, repeated multiplications grow the ciphertext degree and
     * exhaust the noise budget far faster.
     */
    @AIPerformance
    public MemorySegment multiply(MemorySegment a, MemorySegment b) {
        synchronized (nativeLock) {
            ensureOpen();
            MemorySegment result = FheNativeBridge.fhe_multiply(handle, a, b);
            if (result.equals(MemorySegment.NULL)) {
                throw new FheException("fhe_multiply returned NULL");
            }
            // Relinearize: reduces degree-2 ciphertext back to degree-1 (both BFV and CKKS).
            FheNativeBridge.fhe_relinearize(handle, result);
            // Rescale: CKKS only — divides the ciphertext modulus by the scale factor to
            // prevent accumulated scale growth over a chain of multiplications.
            if (scheme == Scheme.CKKS) {
                FheNativeBridge.fhe_rescale(handle, result);
            }
            return result;
        }
    }

    /** Returns the remaining noise budget in bits (BFV only; returns -1 for CKKS). */
    @AIObservability(metrics = {"fhe.noise_budget"},
                     note = "Noise budget drives correctness alerts — dashboards fire when budget drops below safe threshold; do not remove or rename this method")
    public int noiseBudget(MemorySegment ct) {
        synchronized (nativeLock) {
            ensureOpen();
            return FheNativeBridge.fhe_noise_budget(handle, ct);
        }
    }

    /**
     * Set {@code blindbean.noise.guard=false} to decrypt a BFV ciphertext whose noise budget is
     * exhausted instead of refusing it. There is exactly one honest reason to: you are deliberately
     * studying the corruption. It is not a performance switch worth flipping — the budget check is
     * one native call against a decryption that costs far more.
     *
     * <p>Read <em>per call</em>, not cached in a static. A static would only honour the flag when it
     * was set before this class first loaded — so a JVM {@code -D} would work but a programmatic
     * {@code System.setProperty} silently would not, which is a trap, and it would leave the
     * guard-off path untestable. A property lookup is a map read against a decryption that costs
     * milliseconds.
     */
    private static boolean noiseGuardEnabled() {
        return !"false".equalsIgnoreCase(System.getProperty("blindbean.noise.guard"));
    }

    /**
     * Refuses to decrypt a BFV ciphertext whose noise budget is spent.
     *
     * <p>Every homomorphic operation consumes noise budget. At zero, SEAL does not fail — it returns
     * a plausible wrong number. Measured at the default parameters, the fifth chained multiplication
     * decrypted to 49,663 where 64 was expected, with no exception and no warning
     * ({@code load-tests/results/}). That is the last place in this library where wrong data could
     * still be handed back in silence, and it is the same failure shape as the key-rotation
     * corruption and the BFV slot wrap: the computation is finished, the answer is garbage, and
     * nothing says so.
     *
     * <p>So it is refused. A caller who chains multiplies must watch {@link #noiseBudget}; if they
     * do not, this tells them, rather than their users finding out from the data.
     *
     * <p>CKKS has no noise budget (the native call returns -1) — its failure mode is precision
     * decay, not a cliff, and it cannot be detected this way.
     */
    private void requireDecryptable(MemorySegment ct) {
        if (!noiseGuardEnabled() || scheme != Scheme.BFV) {
            return;
        }
        int budget = FheNativeBridge.fhe_noise_budget(handle, ct);
        if (budget <= 0) {
            throw new FheException(
                "Noise budget exhausted (" + budget + " bits): this ciphertext no longer decrypts to "
                + "a meaningful value. Every homomorphic operation spends budget, and multiplies "
                + "spend most of it — at the default parameters BFV survives about four chained "
                + "multiplications. SEAL would have returned a plausible WRONG number here rather "
                + "than failing, which is why this is refused instead.\n"
                + "Watch FheContext.noiseBudget() as you chain operations, raise the polynomial "
                + "modulus degree to buy more depth, or restructure to use fewer multiplies "
                + "(additions are nearly free). To decrypt it anyway, set "
                + "-Dblindbean.noise.guard=false.");
        }
    }

    /** Frees a ciphertext handle. */
    public void freeCiphertext(MemorySegment ct) {
        synchronized (nativeLock) {
            FheNativeBridge.fhe_free_ciphertext(ct);
        }
    }

    private void ensureOpen() {
        if (closed) {
            throw new FheException("FheContext has been closed");
        }
    }

    @AIIdempotent(reason = "Guarded by closed flag; subsequent calls after first close() are no-ops")
    @Override
    public void close() {
        synchronized (nativeLock) {
            if (!closed) {
                closed = true;
                FheNativeBridge.fhe_destroy_context(handle);
                arena.close();
            }
        }
    }
}

package se.deversity.blindbean.fhe;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;

import se.deversity.vibetags.annotations.AICore;
import se.deversity.vibetags.annotations.AILocked;

/**
 * Production-grade Project Panama (FFM API) bridge into Microsoft SEAL.
 * <p>
 * This class provides static downcall method handles for every function in
 * {@code blindbean_fhe.h}. Method handles are resolved once at class-load time
 * and cached for the lifetime of the JVM.
 * <p>
 * <b>DLL resolution:</b> the directory in the system property {@code blindbean.native.path}, or
 * the absolute entries of {@code java.library.path} when that property is unset. The working
 * directory is never searched; see {@link NativeLibraryLocator} for why.
 *
 * Requires {@code --enable-native-access=ALL-UNNAMED} at runtime.
 */
@AICore
@AILocked(reason = "Direct Memory FFM JNI mapping. Avoid breaking SEAL bridge architecture.")
public class FheNativeBridge {

    private static final Linker LINKER = Linker.nativeLinker();
    private static final SymbolLookup SYMBOLS;

    // ── Cached MethodHandles ──────────────────────────────────
    private static final MethodHandle MH_INIT_BFV;
    private static final MethodHandle MH_INIT_CKKS;
    private static final MethodHandle MH_DESTROY_CONTEXT;
    private static final MethodHandle MH_ENCRYPT_LONG;
    private static final MethodHandle MH_DECRYPT_LONG;
    private static final MethodHandle MH_ENCRYPT_LONG_ARRAY;
    private static final MethodHandle MH_DECRYPT_LONG_ARRAY;
    private static final MethodHandle MH_ENCRYPT_DOUBLE;
    private static final MethodHandle MH_DECRYPT_DOUBLE;
    private static final MethodHandle MH_ENCRYPT_DOUBLE_ARRAY;
    private static final MethodHandle MH_DECRYPT_DOUBLE_ARRAY;
    private static final MethodHandle MH_PLAIN_MODULUS;
    private static final MethodHandle MH_SLOT_COUNT;
    private static final MethodHandle MH_ADD;
    private static final MethodHandle MH_SUBTRACT;
    private static final MethodHandle MH_MULTIPLY;
    private static final MethodHandle MH_RELINEARIZE;
    private static final MethodHandle MH_RESCALE;
    private static final MethodHandle MH_NOISE_BUDGET;
    private static final MethodHandle MH_SERIALIZE;
    private static final MethodHandle MH_DESERIALIZE;
    private static final MethodHandle MH_FREE_CIPHERTEXT;
    private static final MethodHandle MH_EXPORT_KEYS;
    private static final MethodHandle MH_IMPORT_KEYS;

    static {
        try {
            // ── Load the native library ───────────────────────────
            loadNativeLibrary();
            SYMBOLS = SymbolLookup.loaderLookup();

            // ── Resolve all downcall handles once ─────────────────
            MH_INIT_BFV = downcall("fhe_init_bfv",
                    FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.JAVA_INT));

            MH_INIT_CKKS = downcall("fhe_init_ckks",
                    FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.JAVA_DOUBLE));

            MH_DESTROY_CONTEXT = downcall("fhe_destroy_context",
                    FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));

            MH_ENCRYPT_LONG = downcall("fhe_encrypt_long",
                    FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));

            // Status plus out-parameter (#221): the old fhe_decrypt_long returned 0 on failure,
            // indistinguishable from an encrypted zero.
            MH_DECRYPT_LONG = downcall("fhe_decrypt_long_checked",
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));

            MH_ENCRYPT_LONG_ARRAY = downcall("fhe_encrypt_long_array",
                    FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));

            MH_DECRYPT_LONG_ARRAY = downcall("fhe_decrypt_long_array",
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));

            MH_ENCRYPT_DOUBLE_ARRAY = downcall("fhe_encrypt_double_array",
                    FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));

            MH_DECRYPT_DOUBLE_ARRAY = downcall("fhe_decrypt_double_array",
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));

            MH_PLAIN_MODULUS = downcall("fhe_plain_modulus",
                    FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));

            MH_SLOT_COUNT = downcall("fhe_slot_count",
                    FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));

            MH_ENCRYPT_DOUBLE = downcall("fhe_encrypt_double",
                    FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_DOUBLE));

            MH_DECRYPT_DOUBLE = downcall("fhe_decrypt_double_checked",
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));

            MH_ADD = downcall("fhe_add",
                    FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));

            MH_SUBTRACT = downcall("fhe_subtract",
                    FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));

            MH_MULTIPLY = downcall("fhe_multiply",
                    FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));

            MH_RELINEARIZE = downcall("fhe_relinearize",
                    FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS));

            MH_RESCALE = downcall("fhe_rescale",
                    FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS));

            MH_NOISE_BUDGET = downcall("fhe_noise_budget",
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));

            MH_SERIALIZE = downcall("fhe_serialize_ciphertext",
                    FunctionDescriptor.of(ValueLayout.JAVA_INT,
                            ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                            ValueLayout.ADDRESS, ValueLayout.ADDRESS));

            MH_DESERIALIZE = downcall("fhe_deserialize_ciphertext",
                    FunctionDescriptor.of(ValueLayout.ADDRESS,
                            ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));

            MH_FREE_CIPHERTEXT = downcall("fhe_free_ciphertext",
                    FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));

            MH_EXPORT_KEYS = downcall("fhe_export_keys",
                    FunctionDescriptor.of(ValueLayout.JAVA_INT,
                            ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));

            MH_IMPORT_KEYS = downcall("fhe_import_keys",
                    FunctionDescriptor.of(ValueLayout.JAVA_INT,
                            ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));
        } catch (Throwable t) {
            System.err.println("CRITICAL: Failed to initialize FheNativeBridge static handles.");
            t.printStackTrace();
            throw t;
        }
    }

    // ── Public API ────────────────────────────────────────────

    public static MemorySegment fhe_init_bfv(int polyModulusDegree) {
        try {
            return (MemorySegment) MH_INIT_BFV.invokeExact(polyModulusDegree);
        } catch (Throwable e) {
            throw new FheException("Failed to call fhe_init_bfv", e);
        }
    }

    public static MemorySegment fhe_init_ckks(int polyModulusDegree, double scale) {
        try {
            return (MemorySegment) MH_INIT_CKKS.invokeExact(polyModulusDegree, scale);
        } catch (Throwable e) {
            throw new FheException("Failed to call fhe_init_ckks", e);
        }
    }

    public static void fhe_destroy_context(MemorySegment ctx) {
        try {
            MH_DESTROY_CONTEXT.invokeExact(ctx);
        } catch (Throwable e) {
            throw new FheException("Failed to call fhe_destroy_context", e);
        }
    }

    public static MemorySegment fhe_encrypt_long(MemorySegment ctx, long value) {
        try {
            return (MemorySegment) MH_ENCRYPT_LONG.invokeExact(ctx, value);
        } catch (Throwable e) {
            throw new FheException("Failed to call fhe_encrypt_long", e);
        }
    }

    /** Native status codes of the checked decrypts, mirroring {@code FHE_*} in blindbean_fhe.h. */
    public static final int FHE_OK = 0;
    public static final int FHE_ERR_ARGUMENT = 1;
    public static final int FHE_ERR_SEAL = 2;

    /** Writes the decrypted value to {@code outValue} (one {@code long}); returns an {@code FHE_*} status. */
    public static int fhe_decrypt_long_checked(MemorySegment ctx, MemorySegment ct, MemorySegment outValue) {
        try {
            return (int) MH_DECRYPT_LONG.invokeExact(ctx, ct, outValue);
        } catch (Throwable e) {
            throw new FheException("Failed to call fhe_decrypt_long_checked", e);
        }
    }

    public static MemorySegment fhe_encrypt_long_array(MemorySegment ctx, MemorySegment valuesArray, long count) {
        try {
            return (MemorySegment) MH_ENCRYPT_LONG_ARRAY.invokeExact(ctx, valuesArray, count);
        } catch (Throwable e) {
            throw new FheException("Failed to call fhe_encrypt_long_array", e);
        }
    }

    public static int fhe_decrypt_long_array(MemorySegment ctx, MemorySegment ct, MemorySegment outBuffer, long maxCount) {
        try {
            return (int) MH_DECRYPT_LONG_ARRAY.invokeExact(ctx, ct, outBuffer, maxCount);
        } catch (Throwable e) {
            throw new FheException("Failed to call fhe_decrypt_long_array", e);
        }
    }

    public static MemorySegment fhe_encrypt_double_array(MemorySegment ctx, MemorySegment valuesArray, long count) {
        try {
            return (MemorySegment) MH_ENCRYPT_DOUBLE_ARRAY.invokeExact(ctx, valuesArray, count);
        } catch (Throwable e) {
            throw new FheException("Failed to call fhe_encrypt_double_array", e);
        }
    }

    public static int fhe_decrypt_double_array(MemorySegment ctx, MemorySegment ct, MemorySegment outBuffer, long maxCount) {
        try {
            return (int) MH_DECRYPT_DOUBLE_ARRAY.invokeExact(ctx, ct, outBuffer, maxCount);
        } catch (Throwable e) {
            throw new FheException("Failed to call fhe_decrypt_double_array", e);
        }
    }

    /** BFV plaintext modulus t. 0 for CKKS, which has none. */
    public static long fhe_plain_modulus(MemorySegment ctx) {
        try {
            return (long) MH_PLAIN_MODULUS.invokeExact(ctx);
        } catch (Throwable e) {
            throw new FheException("Failed to call fhe_plain_modulus", e);
        }
    }

    /** Batching slots: poly_modulus_degree for BFV, half that for CKKS. */
    public static long fhe_slot_count(MemorySegment ctx) {
        try {
            return (long) MH_SLOT_COUNT.invokeExact(ctx);
        } catch (Throwable e) {
            throw new FheException("Failed to call fhe_slot_count", e);
        }
    }

    public static MemorySegment fhe_encrypt_double(MemorySegment ctx, double value) {
        try {
            return (MemorySegment) MH_ENCRYPT_DOUBLE.invokeExact(ctx, value);
        } catch (Throwable e) {
            throw new FheException("Failed to call fhe_encrypt_double", e);
        }
    }

    /** Writes the decrypted value to {@code outValue} (one {@code double}); returns an {@code FHE_*} status. */
    public static int fhe_decrypt_double_checked(MemorySegment ctx, MemorySegment ct, MemorySegment outValue) {
        try {
            return (int) MH_DECRYPT_DOUBLE.invokeExact(ctx, ct, outValue);
        } catch (Throwable e) {
            throw new FheException("Failed to call fhe_decrypt_double_checked", e);
        }
    }

    public static MemorySegment fhe_add(MemorySegment ctx, MemorySegment a, MemorySegment b) {
        try {
            return (MemorySegment) MH_ADD.invokeExact(ctx, a, b);
        } catch (Throwable e) {
            throw new FheException("Failed to call fhe_add", e);
        }
    }

    public static MemorySegment fhe_subtract(MemorySegment ctx, MemorySegment a, MemorySegment b) {
        try {
            return (MemorySegment) MH_SUBTRACT.invokeExact(ctx, a, b);
        } catch (Throwable e) {
            throw new FheException("Failed to call fhe_subtract", e);
        }
    }

    public static MemorySegment fhe_multiply(MemorySegment ctx, MemorySegment a, MemorySegment b) {
        try {
            return (MemorySegment) MH_MULTIPLY.invokeExact(ctx, a, b);
        } catch (Throwable e) {
            throw new FheException("Failed to call fhe_multiply", e);
        }
    }

    public static void fhe_relinearize(MemorySegment ctx, MemorySegment ct) {
        try {
            MH_RELINEARIZE.invokeExact(ctx, ct);
        } catch (Throwable e) {
            throw new FheException("Failed to call fhe_relinearize", e);
        }
    }

    public static void fhe_rescale(MemorySegment ctx, MemorySegment ct) {
        try {
            MH_RESCALE.invokeExact(ctx, ct);
        } catch (Throwable e) {
            throw new FheException("Failed to call fhe_rescale", e);
        }
    }

    public static int fhe_noise_budget(MemorySegment ctx, MemorySegment ct) {
        try {
            return (int) MH_NOISE_BUDGET.invokeExact(ctx, ct);
        } catch (Throwable e) {
            throw new FheException("Failed to call fhe_noise_budget", e);
        }
    }

    public static int fhe_export_keys(MemorySegment ctx, MemorySegment outBuf, MemorySegment outLenPtr) {
        try {
            return (int) MH_EXPORT_KEYS.invokeExact(ctx, outBuf, outLenPtr);
        } catch (Throwable e) {
            throw new FheException("Failed to call fhe_export_keys", e);
        }
    }

    public static int fhe_import_keys(MemorySegment ctx, MemorySegment inBuf, long len) {
        try {
            return (int) MH_IMPORT_KEYS.invokeExact(ctx, inBuf, len);
        } catch (Throwable e) {
            throw new FheException("Failed to call fhe_import_keys", e);
        }
    }

    public static int fhe_serialize_ciphertext(MemorySegment ctx, MemorySegment ct,
                                                MemorySegment outBuf, MemorySegment outLen) {
        try {
            return (int) MH_SERIALIZE.invokeExact(ctx, ct, outBuf, outLen);
        } catch (Throwable e) {
            throw new FheException("Failed to call fhe_serialize_ciphertext", e);
        }
    }

    public static MemorySegment fhe_deserialize_ciphertext(MemorySegment ctx,
                                                            MemorySegment buf, long len) {
        try {
            return (MemorySegment) MH_DESERIALIZE.invokeExact(ctx, buf, len);
        } catch (Throwable e) {
            throw new FheException("Failed to call fhe_deserialize_ciphertext", e);
        }
    }

    public static void fhe_free_ciphertext(MemorySegment ct) {
        try {
            MH_FREE_CIPHERTEXT.invokeExact(ct);
        } catch (Throwable e) {
            throw new FheException("Failed to call fhe_free_ciphertext", e);
        }
    }

    // ── Private helpers ───────────────────────────────────────

    private static MethodHandle downcall(String name, FunctionDescriptor desc) {
        return LINKER.downcallHandle(
                SYMBOLS.find(name).orElseThrow(() ->
                        new FheException("Native symbol not found: " + name)),
                desc
        );
    }

    /**
     * Loads the native library from the file {@link NativeLibraryLocator} picks: the directory in
     * {@code blindbean.native.path}, or an absolute {@code java.library.path} entry.
     */
    private static void loadNativeLibrary() {
        System.load(NativeLibraryLocator.locate(
                System.getProperty(NativeLibraryLocator.PROPERTY),
                System.getProperty("java.library.path")).toString());
    }
}

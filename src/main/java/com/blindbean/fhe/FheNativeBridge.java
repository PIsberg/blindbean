package com.blindbean.fhe;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Production-grade Project Panama (FFM API) bridge into Microsoft SEAL.
 * <p>
 * This class provides static downcall method handles for every function in
 * {@code blindbean_fhe.h}. Method handles are resolved once at class-load time
 * and cached for the lifetime of the JVM.
 * <p>
 * <b>DLL resolution order:</b>
 * <ol>
 *   <li>System property {@code blindbean.native.path} (directory containing the DLL)</li>
 *   <li>{@code src/main/native/} relative to working directory (development convenience)</li>
 *   <li>{@link System#loadLibrary(String)} using {@code java.library.path}</li>
 * </ol>
 *
 * Requires {@code --enable-native-access=ALL-UNNAMED} at runtime.
 */
public class FheNativeBridge {

    private static final Linker LINKER = Linker.nativeLinker();
    private static final SymbolLookup SYMBOLS;

    // ── Cached MethodHandles ──────────────────────────────────
    private static final MethodHandle MH_INIT_BFV;
    private static final MethodHandle MH_INIT_CKKS;
    private static final MethodHandle MH_DESTROY_CONTEXT;
    private static final MethodHandle MH_ENCRYPT_LONG;
    private static final MethodHandle MH_DECRYPT_LONG;
    private static final MethodHandle MH_ENCRYPT_DOUBLE;
    private static final MethodHandle MH_DECRYPT_DOUBLE;
    private static final MethodHandle MH_ADD;
    private static final MethodHandle MH_MULTIPLY;
    private static final MethodHandle MH_RELINEARIZE;
    private static final MethodHandle MH_RESCALE;
    private static final MethodHandle MH_NOISE_BUDGET;
    private static final MethodHandle MH_SERIALIZE;
    private static final MethodHandle MH_DESERIALIZE;
    private static final MethodHandle MH_FREE_CIPHERTEXT;

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

            MH_DECRYPT_LONG = downcall("fhe_decrypt_long",
                    FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.ADDRESS));

            MH_ENCRYPT_DOUBLE = downcall("fhe_encrypt_double",
                    FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_DOUBLE));

            MH_DECRYPT_DOUBLE = downcall("fhe_decrypt_double",
                    FunctionDescriptor.of(ValueLayout.JAVA_DOUBLE, ValueLayout.ADDRESS, ValueLayout.ADDRESS));

            MH_ADD = downcall("fhe_add",
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

    public static long fhe_decrypt_long(MemorySegment ctx, MemorySegment ct) {
        try {
            return (long) MH_DECRYPT_LONG.invokeExact(ctx, ct);
        } catch (Throwable e) {
            throw new FheException("Failed to call fhe_decrypt_long", e);
        }
    }

    public static MemorySegment fhe_encrypt_double(MemorySegment ctx, double value) {
        try {
            return (MemorySegment) MH_ENCRYPT_DOUBLE.invokeExact(ctx, value);
        } catch (Throwable e) {
            throw new FheException("Failed to call fhe_encrypt_double", e);
        }
    }

    public static double fhe_decrypt_double(MemorySegment ctx, MemorySegment ct) {
        try {
            return (double) MH_DECRYPT_DOUBLE.invokeExact(ctx, ct);
        } catch (Throwable e) {
            throw new FheException("Failed to call fhe_decrypt_double", e);
        }
    }

    public static MemorySegment fhe_add(MemorySegment ctx, MemorySegment a, MemorySegment b) {
        try {
            return (MemorySegment) MH_ADD.invokeExact(ctx, a, b);
        } catch (Throwable e) {
            throw new FheException("Failed to call fhe_add", e);
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
     * Loads the native library using a prioritized search strategy:
     * 1. System property blindbean.native.path (directory path)
     * 2. src/main/native/ relative to cwd (dev convenience)
     * 3. System loadLibrary (java.library.path)
     */
    private static void loadNativeLibrary() {
        String dllName = System.mapLibraryName("blindbean_fhe"); // blindbean_fhe.dll or libblindbean_fhe.so

        // Strategy 1: System property
        String nativePath = System.getProperty("blindbean.native.path");
        if (nativePath != null) {
            Path candidate = Paths.get(nativePath, dllName);
            if (Files.exists(candidate)) {
                System.load(candidate.toAbsolutePath().toString());
                return;
            }
            // Also try without the lib prefix on Linux (CMake output is "blindbean_fhe.so")
            candidate = Paths.get(nativePath, "blindbean_fhe.dll");
            if (Files.exists(candidate)) {
                System.load(candidate.toAbsolutePath().toString());
                return;
            }
        }

        // Strategy 2: Development path relative to cwd
        Path devPath = Paths.get("src/main/native", dllName).toAbsolutePath();
        if (Files.exists(devPath)) {
            System.load(devPath.toString());
            return;
        }
        // Also check CMake build output directories
        for (String buildDir : new String[]{"build-native/Release", "build-native/Debug", "build-native"}) {
            Path buildPath = Paths.get(buildDir, dllName).toAbsolutePath();
            if (Files.exists(buildPath)) {
                System.load(buildPath.toString());
                return;
            }
        }

        // Strategy 3: System library path
        try {
            System.loadLibrary("blindbean_fhe");
        } catch (UnsatisfiedLinkError e) {
            throw new FheException(
                    "Cannot load blindbean_fhe native library. Searched: " +
                    "blindbean.native.path=" + nativePath + ", " +
                    "src/main/native/, build-native/, java.library.path. " +
                    "Ensure the SEAL-backed DLL is built (see README for CMake instructions).", e);
        }
    }
}

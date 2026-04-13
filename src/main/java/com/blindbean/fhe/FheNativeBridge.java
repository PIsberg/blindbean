package com.blindbean.fhe;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Hand-crafted Project Panama (FFM API) bridge.
 * This class mirrors the layout of what 'jextract' generates from blindbean_fhe.h.
 * Included directly to avoid requiring a local jextract installation.
 */
public class FheNativeBridge {
    private static final Linker LINKER = Linker.nativeLinker();
    private static final SymbolLookup SYMBOLS;

    static {
        // Load the dummy DLL. Requires passing --enable-native-access=ALL-UNNAMED
        Path dllPath = Paths.get("src/main/native/blindbean_fhe.dll").toAbsolutePath();
        System.load(dllPath.toString());
        SYMBOLS = SymbolLookup.loaderLookup();
    }

    // fhe_init_bfv
    public static MemorySegment fhe_init_bfv(int polyModulusDegree) {
        try {
            var methodHandle = LINKER.downcallHandle(
                SYMBOLS.find("fhe_init_bfv").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.JAVA_INT)
            );
            return (MemorySegment) methodHandle.invokeExact(polyModulusDegree);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to call fhe_init_bfv", e);
        }
    }

    // fhe_destroy_context
    public static void fhe_destroy_context(MemorySegment ctx) {
        try {
            var methodHandle = LINKER.downcallHandle(
                SYMBOLS.find("fhe_destroy_context").orElseThrow(),
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS)
            );
            methodHandle.invokeExact(ctx);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to call fhe_destroy_context", e);
        }
    }

    // fhe_encrypt_long
    public static MemorySegment fhe_encrypt_long(MemorySegment ctx, long value) {
        try {
            var methodHandle = LINKER.downcallHandle(
                SYMBOLS.find("fhe_encrypt_long").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG)
            );
            return (MemorySegment) methodHandle.invokeExact(ctx, value);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to call fhe_encrypt_long", e);
        }
    }

    // fhe_decrypt_long
    public static long fhe_decrypt_long(MemorySegment ctx, MemorySegment ct) {
        try {
            var methodHandle = LINKER.downcallHandle(
                SYMBOLS.find("fhe_decrypt_long").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.ADDRESS)
            );
            return (long) methodHandle.invokeExact(ctx, ct);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to call fhe_decrypt_long", e);
        }
    }

    // fhe_add
    public static MemorySegment fhe_add(MemorySegment ctx, MemorySegment a, MemorySegment b) {
        try {
            var methodHandle = LINKER.downcallHandle(
                SYMBOLS.find("fhe_add").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS)
            );
            return (MemorySegment) methodHandle.invokeExact(ctx, a, b);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to call fhe_add", e);
        }
    }
}

package com.blindbean.fhe;

import com.blindbean.annotations.Scheme;
import com.blindbean.core.Ciphertext;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.Arena;
import java.lang.foreign.ValueLayout;

/**
 * An AutoCloseable wrapper around a native FHE ciphertext handle.
 * Provides serialization support for persistence and conversion to BlindBean's {@link Ciphertext} record.
 */
public class FheCiphertextNative implements AutoCloseable {

    private final MemorySegment handle;
    private final FheContext context;
    private volatile boolean freed = false;

    public FheCiphertextNative(MemorySegment handle, FheContext context) {
        if (handle.equals(MemorySegment.NULL)) {
            throw new FheException("Cannot create FheCiphertextNative from NULL handle");
        }
        this.handle  = handle;
        this.context = context;
    }

    /** Returns the raw native handle. */
    public MemorySegment handle() {
        ensureValid();
        return handle;
    }

    /**
     * Serializes this ciphertext to a byte array for storage/transport.
     * The byte array can later be deserialized with {@link #deserialize(FheContext, byte[])}.
     */
    public byte[] serialize() {
        ensureValid();
        MemorySegment ctx = context.handle();

        // First call: query required size
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment lenSeg = arena.allocate(ValueLayout.JAVA_LONG);
            lenSeg.set(ValueLayout.JAVA_LONG, 0, 0L);

            FheNativeBridge.fhe_serialize_ciphertext(ctx, handle, MemorySegment.NULL, lenSeg);
            long requiredSize = lenSeg.get(ValueLayout.JAVA_LONG, 0);

            if (requiredSize <= 0) {
                throw new FheException("Failed to query serialization size");
            }

            // Second call: actual serialization
            MemorySegment buf = arena.allocate(requiredSize);
            lenSeg.set(ValueLayout.JAVA_LONG, 0, requiredSize);

            int rc = FheNativeBridge.fhe_serialize_ciphertext(ctx, handle, buf, lenSeg);
            if (rc != 0) {
                throw new FheException("Serialization failed", rc);
            }

            long actualLen = lenSeg.get(ValueLayout.JAVA_LONG, 0);
            return buf.asSlice(0, actualLen).toArray(ValueLayout.JAVA_BYTE);
        }
    }

    /**
     * Deserializes a ciphertext from a byte array previously produced by {@link #serialize()}.
     */
    public static FheCiphertextNative deserialize(FheContext context, byte[] data) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment buf = arena.allocateFrom(ValueLayout.JAVA_BYTE, data);
            MemorySegment h = FheNativeBridge.fhe_deserialize_ciphertext(context.handle(), buf, data.length);
            return new FheCiphertextNative(h, context);
        }
    }

    /**
     * Converts this native ciphertext to BlindBean's portable {@link Ciphertext} record.
     * The serialized bytes are stored in the Ciphertext for scheme-agnostic persistence.
     */
    public Ciphertext toBlindCiphertext() {
        byte[] serialized = serialize();
        return Ciphertext.fromBytes(serialized, context.scheme());
    }

    /**
     * Reconstructs a native ciphertext from a BlindBean {@link Ciphertext} record.
     */
    public static FheCiphertextNative fromBlindCiphertext(FheContext context, Ciphertext ct) {
        return deserialize(context, ct.getBytes());
    }

    private void ensureValid() {
        if (freed) {
            throw new FheException("FheCiphertextNative has been freed");
        }
    }

    @Override
    public void close() {
        if (!freed) {
            freed = true;
            FheNativeBridge.fhe_free_ciphertext(handle);
        }
    }
}

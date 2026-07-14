package com.blindbean.fhe;

import com.blindbean.annotations.Scheme;
import com.blindbean.core.Ciphertext;
import com.blindbean.core.KeyTag;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.Arena;
import java.lang.foreign.ValueLayout;

import se.deversity.vibetags.annotations.AIAudit;
import se.deversity.vibetags.annotations.AIContract;
import se.deversity.vibetags.annotations.AIIdempotent;
import se.deversity.vibetags.annotations.AIStrictExceptions;

/**
 * An AutoCloseable wrapper around a native FHE ciphertext handle.
 * Provides serialization support for persistence and conversion to BlindBean's {@link Ciphertext} record.
 *
 * <h3>Serialization format (v1)</h3>
 * <pre>
 *   [0–1]  magic    : 0x42 0x4C  ("BL")
 *   [2]    version  : 0x01
 *   [3]    scheme   : 0x00 = BFV, 0x01 = CKKS
 *   [4–7]  polyDeg  : big-endian int (polyModulusDegree)
 *   [8–9]  reserved : 0x00 0x00
 *   [10..] payload  : raw SEAL ciphertext bytes
 * </pre>
 */
@AIAudit(checkFor = {"Resource Leaks", "Memory Segment lifecycle", "Double-free"})
@AIContract(reason = "Serialization format and handle lifecycle are part of the public FFM contract; do not change method signatures")
@AIStrictExceptions
public class FheCiphertextNative implements AutoCloseable {

    // ── Serialization format constants ────────────────────────
    private static final byte MAGIC_0  = 0x42; // 'B'
    private static final byte MAGIC_1  = 0x4C; // 'L'
    private static final byte VERSION  = 0x01;
    private static final int  HEADER_LEN = 10;

    private final MemorySegment handle;
    private final FheContext context;
    private final Object freeLock = new Object();
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
     * Serializes this ciphertext to a versioned byte array for storage/transport.
     * The format is documented in the class Javadoc. The byte array can later be
     * deserialized with {@link #deserialize(FheContext, byte[])}.
     */
    public byte[] serialize() {
        ensureValid();
        MemorySegment ctx = context.handle();

        try (Arena arena = Arena.ofConfined()) {
            // First call: query required SEAL payload size
            MemorySegment lenSeg = arena.allocate(ValueLayout.JAVA_LONG);
            lenSeg.set(ValueLayout.JAVA_LONG, 0, 0L);
            FheNativeBridge.fhe_serialize_ciphertext(ctx, handle, MemorySegment.NULL, lenSeg);
            long requiredSize = lenSeg.get(ValueLayout.JAVA_LONG, 0);
            if (requiredSize <= 0) {
                throw new FheException("Failed to query serialization size");
            }

            // Second call: actual serialization into buffer
            MemorySegment buf = arena.allocate(requiredSize);
            lenSeg.set(ValueLayout.JAVA_LONG, 0, requiredSize);
            int rc = FheNativeBridge.fhe_serialize_ciphertext(ctx, handle, buf, lenSeg);
            if (rc != 0) {
                throw new FheException("Serialization failed", rc);
            }
            long actualLen = lenSeg.get(ValueLayout.JAVA_LONG, 0);
            byte[] sealBytes = buf.asSlice(0, actualLen).toArray(ValueLayout.JAVA_BYTE);

            // Prepend the 10-byte BlindBean header
            byte schemeCode = (byte) (context.scheme() == Scheme.BFV ? 0 : 1);
            int  polyDeg    = context.polyModulusDegree();
            byte[] out = new byte[HEADER_LEN + sealBytes.length];
            out[0] = MAGIC_0;
            out[1] = MAGIC_1;
            out[2] = VERSION;
            out[3] = schemeCode;
            out[4] = (byte) (polyDeg >>> 24);
            out[5] = (byte) (polyDeg >>> 16);
            out[6] = (byte) (polyDeg >>>  8);
            out[7] = (byte)  polyDeg;
            out[8] = 0x00; // reserved
            out[9] = 0x00; // reserved
            System.arraycopy(sealBytes, 0, out, HEADER_LEN, sealBytes.length);
            return out;
        }
    }

    /**
     * Deserializes a ciphertext from a versioned byte array produced by {@link #serialize()}.
     *
     * @throws FheException if the header magic is invalid, the version is unsupported,
     *                      or the scheme in the header does not match the provided context
     */
    public static FheCiphertextNative deserialize(FheContext context, byte[] data) {
        if (data.length < HEADER_LEN) {
            throw new FheException(
                "Serialized ciphertext too short (" + data.length + " bytes); "
                + "minimum is " + HEADER_LEN + " bytes. "
                + "Data may be corrupt or produced by an older version without header support.");
        }
        if (data[0] != MAGIC_0 || data[1] != MAGIC_1) {
            throw new FheException(String.format(
                "Invalid ciphertext header magic: expected 0x%02X%02X ('BL'), got 0x%02X%02X. "
                + "Data may be corrupt or produced before serialization versioning was introduced.",
                MAGIC_0, MAGIC_1, data[0] & 0xFF, data[1] & 0xFF));
        }
        if (data[2] != VERSION) {
            throw new FheException(
                "Unsupported ciphertext format version: " + (data[2] & 0xFF)
                + "; this build supports version " + (VERSION & 0xFF) + ".");
        }
        byte expectedSchemeCode = (byte) (context.scheme() == Scheme.BFV ? 0 : 1);
        if (data[3] != expectedSchemeCode) {
            String headerScheme = (data[3] == 0) ? "BFV" : (data[3] == 1) ? "CKKS" : "unknown(" + data[3] + ")";
            throw new FheException(
                "Ciphertext scheme mismatch: header declares " + headerScheme
                + " but context is " + context.scheme() + ".");
        }

        // Strip header and pass raw SEAL bytes to the native bridge
        byte[] sealBytes = new byte[data.length - HEADER_LEN];
        System.arraycopy(data, HEADER_LEN, sealBytes, 0, sealBytes.length);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment buf = arena.allocateFrom(ValueLayout.JAVA_BYTE, sealBytes);
            MemorySegment h = FheNativeBridge.fhe_deserialize_ciphertext(context.handle(), buf, sealBytes.length);
            return new FheCiphertextNative(h, context);
        }
    }

    /**
     * Converts this native ciphertext to BlindBean's portable {@link Ciphertext} record.
     * The serialized bytes are stored in the Ciphertext for scheme-agnostic persistence.
     */
    public Ciphertext toBlindCiphertext() {
        byte[] serialized = serialize();
        return Ciphertext.fromBytes(KeyTag.wrap(context.keyTag(), serialized), context.scheme());
    }

    /**
     * Reconstructs a native ciphertext from a BlindBean {@link Ciphertext} record.
     *
     * <p>Refuses a ciphertext belonging to a different key generation. SEAL would not have caught
     * it: two contexts built from the same parameters share a {@code parms_id}, so a foreign
     * ciphertext deserializes cleanly and then decrypts to noise rather than failing. That is the
     * shape of the key-rotation corruption this check exists to stop — see {@link KeyTag}.
     *
     * @throws com.blindbean.core.WrongKeyException if it was encrypted under other keys
     */
    public static FheCiphertextNative fromBlindCiphertext(FheContext context, Ciphertext ct) {
        byte[] payload = KeyTag.verifyAndUnwrap(
            ct.getBytes(), context.keyTag(), "use this " + context.scheme() + " ciphertext");
        return deserialize(context, payload);
    }

    private void ensureValid() {
        if (freed) {
            throw new FheException("FheCiphertextNative has been freed");
        }
    }

    @AIIdempotent(reason = "Guarded by freed flag; calling close() on an already-freed handle is a no-op")
    @Override
    public void close() {
        // The test-and-set must be atomic: a plain volatile read/write lets two threads both
        // observe freed == false and both hand the same handle to the native allocator.
        synchronized (freeLock) {
            if (!freed) {
                freed = true;
                FheNativeBridge.fhe_free_ciphertext(handle);
            }
        }
    }
}

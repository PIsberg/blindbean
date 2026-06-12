package com.blindbean.core;

import com.blindbean.annotations.Scheme;

import java.util.Objects;

import se.deversity.vibetags.annotations.AIDomainModel;
import se.deversity.vibetags.annotations.AIImmutable;
import se.deversity.vibetags.annotations.AIPublicAPI;
import se.deversity.vibetags.annotations.AISchemaSafe;

/**
 * An immutable representation of encrypted data.
 * <p>
 * For Paillier (PHE), data is stored as a hex-encoded BigInteger string.
 * For SEAL-backed schemes (BFV, CKKS), data is stored as raw serialized bytes
 * with hex encoding provided for backward compatibility.
 */
@AIImmutable(note = "Java record — hexData and scheme are final record components; do not convert to a mutable class")
@AISchemaSafe
@AIPublicAPI
@AIDomainModel(allow = {"com.blindbean.annotations.Scheme"})
public record Ciphertext(String hexData, Scheme scheme) {
    public Ciphertext {
        Objects.requireNonNull(hexData, "hexData must not be null");
        Objects.requireNonNull(scheme, "scheme must not be null");
        if ((hexData.length() & 1) != 0) {
            throw new IllegalArgumentException(
                "Ciphertext hexData has odd length " + hexData.length()
                + "; a valid hex-encoded byte array must have even length");
        }
        for (int i = 0, n = hexData.length(); i < n; i++) {
            char c = hexData.charAt(i);
            if ((c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F')) {
                throw new IllegalArgumentException(
                    "Ciphertext hexData contains invalid hex character '" + c
                    + "' at index " + i);
            }
        }
    }
    
    // Helper to extract bytes from hex encoding
    public byte[] getBytes() {
        int len = hexData.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexData.charAt(i), 16) << 4)
                                 + Character.digit(hexData.charAt(i+1), 16));
        }
        return data;
    }

    public static Ciphertext fromBytes(byte[] bytes, Scheme scheme) {
        StringBuilder hex = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            hex.append(String.format("%02x", b));
        }
        return new Ciphertext(hex.toString(), scheme);
    }

    /**
     * Returns the size of the serialized ciphertext in bytes.
     * Useful for monitoring FHE ciphertext expansion.
     */
    public int sizeInBytes() {
        return hexData.length() / 2;
    }

    /**
     * Returns true if this ciphertext belongs to a SEAL-backed FHE scheme.
     */
    public boolean isFhe() {
        return scheme == Scheme.BFV || scheme == Scheme.CKKS;
    }
}

package com.blindbean.core;

import com.blindbean.annotations.Scheme;

import java.util.Objects;

/**
 * An immutable representation of encrypted data.
 * <p>
 * For Paillier (PHE), data is stored as a hex-encoded BigInteger string.
 * For SEAL-backed schemes (BFV, CKKS), data is stored as raw serialized bytes
 * with hex encoding provided for backward compatibility.
 */
public record Ciphertext(String hexData, Scheme scheme) {
    public Ciphertext {
        Objects.requireNonNull(hexData);
        Objects.requireNonNull(scheme);
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

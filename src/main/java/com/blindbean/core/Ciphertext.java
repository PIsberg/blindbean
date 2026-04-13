package com.blindbean.core;

import com.blindbean.annotations.Scheme;

import java.util.Objects;

/**
 * An immutable representation of encrypted data.
 */
public record Ciphertext(String hexData, Scheme scheme) {
    public Ciphertext {
        Objects.requireNonNull(hexData);
        Objects.requireNonNull(scheme);
    }
    
    // Helper to extract bytes if needed
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
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02x", b));
        }
        return new Ciphertext(hex.toString(), scheme);
    }
}

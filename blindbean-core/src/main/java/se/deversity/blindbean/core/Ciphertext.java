package se.deversity.blindbean.core;

import se.deversity.blindbean.annotations.Scheme;

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
@AIDomainModel(allow = {"se.deversity.blindbean.annotations.Scheme"})
public record Ciphertext(String hexData, Scheme scheme) {

    /**
     * Lowercase hex codec, matching the historical {@code String.format("%02x", b)} encoding
     * byte for byte. SEAL ciphertexts run to hundreds of kilobytes and every homomorphic
     * operation re-encodes one, so the per-byte formatter was the dominant cost on that path.
     */
    private static final java.util.HexFormat HEX = java.util.HexFormat.of();

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
        return HEX.parseHex(hexData);
    }

    public static Ciphertext fromBytes(byte[] bytes, Scheme scheme) {
        return new Ciphertext(HEX.formatHex(bytes), scheme);
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

package com.blindbean.core;

import java.util.HexFormat;

/**
 * Thrown when a ciphertext is used under a key generation that did not produce it.
 *
 * <p>Before ciphertexts were stamped ({@link KeyTag}) this condition was undetectable: Paillier
 * and SEAL both decrypt a foreign ciphertext to a well-formed wrong answer rather than failing,
 * so the mistake surfaced as corrupted data, if at all. Anything that reaches this exception is
 * a case that used to be silently destructive.
 *
 * <p>Far and away the most common cause is re-running a key rotation over rows that were already
 * rotated — see the guidance in the message.
 */
public final class WrongKeyException extends IllegalArgumentException {

    private static final long serialVersionUID = 1L;

    private final transient byte[] expectedTag;
    private final transient byte[] actualTag;

    WrongKeyException(String operation, byte[] expectedTag, byte[] actualTag) {
        super(message(operation, expectedTag, actualTag));
        this.expectedTag = expectedTag.clone();
        this.actualTag = actualTag.clone();
    }

    /** Key-generation fingerprint of the key that was used. Not key material. */
    public byte[] expectedTag() {
        return expectedTag.clone();
    }

    /** Key-generation fingerprint stamped on the ciphertext. Not key material. */
    public byte[] actualTag() {
        return actualTag.clone();
    }

    private static String message(String operation, byte[] expected, byte[] actual) {
        HexFormat hex = HexFormat.of();
        return "Cannot " + operation + ": this ciphertext was encrypted under key generation "
             + hex.formatHex(actual) + ", but the key in use is generation "
             + hex.formatHex(expected) + ". Decrypting it under the wrong key would not fail — it "
             + "would return a plausible but meaningless value — so it is refused instead.\n"
             + "If this is a re-run of a key rotation that did not finish, this value has ALREADY "
             + "been rotated: skip it rather than rotating it again. Rotating it a second time is "
             + "what this check exists to prevent.";
    }
}

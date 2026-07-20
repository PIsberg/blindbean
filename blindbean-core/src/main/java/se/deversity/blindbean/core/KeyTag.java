package se.deversity.blindbean.core;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.jspecify.annotations.Nullable;

/**
 * Binds a ciphertext to the key generation that produced it.
 *
 * <p>Homomorphic ciphertexts carry no identity of their own. A Paillier ciphertext is just a
 * number, and decrypting one under the wrong key does not fail — by the Carmichael property
 * {@code c^lambda = 1 (mod n)} for <em>any</em> {@code c} coprime to {@code n}, so the
 * {@code L()} division stays exact and decryption hands back a well-formed but meaningless
 * value. SEAL is no safer here: two contexts built from the same parameters share a
 * {@code parms_id}, so a ciphertext from one deserializes cleanly into the other and decrypts
 * to noise. There is no in-band signal to detect any of this, at any key size.
 *
 * <p>That mattered most during key rotation. Rotation is decrypt-then-encrypt and is not atomic
 * across a datastore, so a batch that dies halfway leaves some rows rotated and some not — and
 * re-running it fed the already-rotated rows back through {@code decrypt(oldKey)}, silently
 * replacing real values with garbage that was then validly re-encrypted. The damage was
 * undetectable and, once the old key was retired, unrecoverable.
 *
 * <p>So the key generation is now stamped into the payload itself. It has to live <em>in</em> the
 * payload rather than beside it, because {@code hexData} is the only thing that reaches the
 * caller's datastore: the generated wrappers persist {@code entity.setX(ct.hexData())} and nothing
 * else, so a tag held anywhere but inside those bytes would be dropped on the way to disk.
 *
 * <h2>Wire format</h2>
 * <pre>
 *   magic 'B','B','C','T' | version (1) | tagLen (16) | tag[16] | ciphertext bytes...
 * </pre>
 *
 * <p>Payloads written before this existed carry no header. They are read as <em>legacy</em>
 * (untagged) and accepted, because refusing them would make every ciphertext already on disk
 * undecryptable; rotating or re-encrypting one produces a tagged payload, so a dataset heals as
 * it is written. A legacy ciphertext therefore keeps the old silent-corruption exposure until it
 * has been rewritten once — this closes the hole going forward, it does not retro-fit safety onto
 * bytes that were never stamped.
 *
 * <p>The tag is a truncated SHA-256 over key material with a domain-separation prefix. For
 * Paillier it is derived from the <em>public</em> modulus {@code n}. For BFV/CKKS it is derived
 * from the serialized SEAL key blob, which is what {@code FheContext.exportState()} already
 * writes to a key file — a 128-bit one-way digest of it discloses nothing recoverable, and it is
 * stable across an export/import round trip, which a random per-context id would not be (every
 * restart would repudiate its own ciphertexts).
 */
public final class KeyTag {

    private static final byte[] MAGIC = {'B', 'B', 'C', 'T'};
    private static final byte VERSION = 1;

    /** Bytes of SHA-256 kept. 128 bits — collision here means a false ACCEPT, so it is not a place to economise. */
    public static final int TAG_LENGTH = 16;

    /** magic(4) + version(1) + tagLen(1) + tag(16). */
    private static final int HEADER_LENGTH = MAGIC.length + 2 + TAG_LENGTH;

    private static final byte[] DOMAIN = "blindbean-keytag-v1".getBytes(StandardCharsets.UTF_8);

    private KeyTag() {
    }

    /**
     * Derives the stable 16-byte identifier of a key generation.
     *
     * @param keyMaterial Paillier: {@code n.toByteArray()}. BFV/CKKS: the serialized SEAL key blob.
     */
    public static byte[] derive(byte[] keyMaterial) {
        MessageDigest sha = sha256();
        sha.update(DOMAIN);
        sha.update(keyMaterial);
        return Arrays.copyOf(sha.digest(), TAG_LENGTH);
    }

    /** Stamps {@code payload} with {@code tag}. */
    public static byte[] wrap(byte[] tag, byte[] payload) {
        if (tag.length != TAG_LENGTH) {
            throw new IllegalArgumentException(
                "Key tag must be " + TAG_LENGTH + " bytes, got " + tag.length);
        }
        byte[] out = new byte[HEADER_LENGTH + payload.length];
        System.arraycopy(MAGIC, 0, out, 0, MAGIC.length);
        out[MAGIC.length] = VERSION;
        out[MAGIC.length + 1] = (byte) TAG_LENGTH;
        System.arraycopy(tag, 0, out, MAGIC.length + 2, TAG_LENGTH);
        System.arraycopy(payload, 0, out, HEADER_LENGTH, payload.length);
        return out;
    }

    /**
     * The tag stamped on {@code enveloped}, or {@code null} if it is a legacy untagged payload.
     *
     * <p>A legacy ciphertext is raw key-dependent bytes and could in principle open with the six
     * header bytes by chance; the odds are 2^-48 per value, and the alternative — no legacy path —
     * would mean refusing to decrypt every ciphertext written before this format existed.
     */
    public static byte @Nullable [] tagOf(byte[] enveloped) {
        if (!isTagged(enveloped)) {
            return null;
        }
        return Arrays.copyOfRange(enveloped, MAGIC.length + 2, HEADER_LENGTH);
    }

    /** The ciphertext bytes, with any header stripped. A legacy payload is returned whole. */
    public static byte[] payloadOf(byte[] enveloped) {
        if (!isTagged(enveloped)) {
            return enveloped;
        }
        return Arrays.copyOfRange(enveloped, HEADER_LENGTH, enveloped.length);
    }

    public static boolean isTagged(byte[] b) {
        if (b.length <= HEADER_LENGTH) {
            return false;
        }
        for (int i = 0; i < MAGIC.length; i++) {
            if (b[i] != MAGIC[i]) {
                return false;
            }
        }
        return b[MAGIC.length] == VERSION && b[MAGIC.length + 1] == (byte) TAG_LENGTH;
    }

    /**
     * Verifies that {@code enveloped} belongs to {@code expected}, and returns its payload.
     *
     * @throws WrongKeyException if it carries a different generation's tag
     */
    public static byte[] verifyAndUnwrap(byte[] enveloped, byte[] expected, String operation) {
        byte[] actual = tagOf(enveloped);
        if (actual != null && !MessageDigest.isEqual(actual, expected)) {
            throw new WrongKeyException(operation, expected, actual);
        }
        return payloadOf(enveloped);
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required by every Java platform", e);
        }
    }
}

package se.deversity.blindbean.core;

import se.deversity.blindbean.annotations.Scheme;

import org.junit.jupiter.api.Test;

import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Encoding tests for {@link Ciphertext}. The hex encoding is a persisted format, so it must
 * stay byte-identical to the original {@code String.format("%02x", b)} encoder.
 */
public class CiphertextTest {

    /** The encoding fromBytes() used before it was replaced with HexFormat. */
    private static String legacyEncode(byte[] bytes) {
        StringBuilder hex = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }

    @Test
    public void encodingIsByteIdenticalToTheLegacyFormatter() {
        byte[] payload = new byte[4096];
        new Random(20260713L).nextBytes(payload);

        assertEquals(legacyEncode(payload), Ciphertext.fromBytes(payload, Scheme.BFV).hexData(),
            "hex encoding is persisted — it must not drift from the original format");
    }

    @Test
    public void coversEveryByteValueAndRoundTrips() {
        byte[] allBytes = new byte[256];
        for (int i = 0; i < 256; i++) {
            allBytes[i] = (byte) i;
        }

        Ciphertext ct = Ciphertext.fromBytes(allBytes, Scheme.PAILLIER);
        assertEquals(legacyEncode(allBytes), ct.hexData(), "every byte value must encode identically");
        assertArrayEquals(allBytes, ct.getBytes(), "bytes must survive the hex round-trip");
        assertEquals(256, ct.sizeInBytes());
    }

    @Test
    public void emptyPayloadRoundTrips() {
        Ciphertext ct = Ciphertext.fromBytes(new byte[0], Scheme.PAILLIER);
        assertEquals("", ct.hexData());
        assertArrayEquals(new byte[0], ct.getBytes());
        assertEquals(0, ct.sizeInBytes());
    }

    @Test
    public void uppercaseHexIsAcceptedAndDecodesTheSameAsLowercase() {
        // The constructor admits either case, so getBytes() must too.
        assertArrayEquals(new Ciphertext("0aff10", Scheme.BFV).getBytes(),
                          new Ciphertext("0AFF10", Scheme.BFV).getBytes());
    }

    @Test
    public void malformedHexIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> new Ciphertext("abc", Scheme.BFV));
        assertThrows(IllegalArgumentException.class, () -> new Ciphertext("zz", Scheme.BFV));
    }
}

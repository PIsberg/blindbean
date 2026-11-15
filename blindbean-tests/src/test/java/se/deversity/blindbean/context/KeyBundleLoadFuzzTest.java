package se.deversity.blindbean.context;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import se.deversity.blindbean.fhe.FheException;
import se.deversity.blindbean.math.PaillierKeyPair;

import java.io.IOException;
import java.io.InvalidClassException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Fuzzes {@link BlindContext#loadKeys(String)}, the one place BlindBean deserializes bytes it did
 * not produce in this process. A key file can be tampered with on disk, so the contract under test
 * is: whatever the bytes, {@code loadKeys} either restores a key bundle or throws
 * {@link FheException}. Any other exception or {@link Error} escaping it (a raw
 * {@code ClassCastException}, a {@code StackOverflowError} from a deep object graph, an
 * {@code OutOfMemoryError} from a forged array length) is a finding.
 *
 * <p>In a normal {@code mvn verify} Jazzer runs in regression mode: {@link #loadKeysOnArbitraryBytes}
 * executes once per stored crash/seed input and needs no instrumentation. Run it as a real fuzzer
 * with {@code JAZZER_FUZZ=1}, see {@code docs/CI-NOTES.md}. The {@code @Test} cases below pin the
 * same contract on hand-built inputs (a valid bundle, then truncated and bit-flipped copies of it),
 * so the CI gate covers the interesting inputs even without a fuzzing campaign.
 *
 * <p>Paillier-only bundles, so nothing here needs the native library.
 */
public class KeyBundleLoadFuzzTest {

    @TempDir
    Path tempDir;

    @AfterEach
    public void teardown() {
        BlindContext.clear();
    }

    /**
     * A valid bundle for the fuzzer to mutate, generated once per JVM. Starting from raw bytes
     * alone the fuzzer rarely gets past the stream header (36 edges in a 60 s run), and a
     * committed seed file would be a key-bundle test fixture, which the KeyBundle privacy
     * guardrail rules out. Generated in-process, the key never leaves the test JVM.
     */
    private static byte @org.jspecify.annotations.Nullable [] validBundle;

    @FuzzTest(maxDuration = "60s")
    public void loadKeysOnArbitraryBytes(FuzzedDataProvider data) throws IOException {
        if (data.consumeBoolean()) {
            assertLoadKeysContract(data.consumeRemainingAsBytes());
            return;
        }
        // Mutate a real bundle: a fuzzer-chosen truncation plus up to 16 byte overwrites, so the
        // inputs reach class descriptors, field values and BigInteger magnitudes.
        byte[] bundle = validBundleForFuzzing();
        byte[] mutated = Arrays.copyOf(bundle, data.consumeInt(1, bundle.length));
        int edits = data.consumeInt(0, 16);
        for (int i = 0; i < edits && data.remainingBytes() >= 5; i++) {
            mutated[data.consumeInt(0, mutated.length - 1)] = data.consumeByte();
        }
        assertLoadKeysContract(mutated);
    }

    private byte[] validBundleForFuzzing() throws IOException {
        byte[] cached = validBundle;
        if (cached == null) {
            cached = exportedPaillierBundle();
            validBundle = cached;
        }
        return cached;
    }

    @Test
    public void validBundleLoads() throws IOException {
        byte[] valid = exportedPaillierBundle();
        Path file = write(valid);
        assertDoesNotThrow(() -> BlindContext.loadKeys(file.toString()));
    }

    @Test
    public void emptyAndGarbageFilesFailWithFheException() {
        assertLoadKeysContract(new byte[0]);
        assertLoadKeysContract(new byte[] {(byte) 0xAC, (byte) 0xED, 0x00, 0x05});   // stream header only
        assertLoadKeysContract("not a key bundle".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    }

    @Test
    public void everyTruncationOfAValidBundleHonoursTheContract() throws IOException {
        byte[] valid = exportedPaillierBundle();
        for (int len = 0; len < valid.length; len++) {
            assertLoadKeysContract(Arrays.copyOf(valid, len));
        }
    }

    @Test
    public void aBitFlipAtEveryOffsetOfAValidBundleHonoursTheContract() throws IOException {
        byte[] valid = exportedPaillierBundle();
        // One flip per byte, rotating through the bit positions: every offset of the stream
        // (headers, class descriptors, lengths, BigInteger magnitudes) gets corrupted once, at an
        // eighth of the cost of all eight flips per byte. The fuzzer covers the rest.
        for (int i = 0; i < valid.length; i++) {
            byte[] mutated = valid.clone();
            mutated[i] ^= (byte) (1 << (i % 8));
            assertLoadKeysContract(mutated);
        }
    }

    /**
     * A 1 KB key file whose BigInteger magnitude claims {@code Integer.MAX_VALUE - 16} bytes.
     * Before the size bound, ObjectInputStream allocated the claimed ~2 GB up front: on a 512 MB
     * heap that was an {@link OutOfMemoryError} escaping {@code loadKeys}, on a big heap a 2 GB
     * allocation before an {@code EOFException}. The filter must reject the length before any
     * allocation, which surfaces as an {@link java.io.InvalidClassException} ("filter status:
     * REJECTED") under the {@link FheException}.
     */
    @Test
    public void aForgedArrayLengthIsRejectedBeforeAllocation() throws IOException {
        byte[] forged = exportedPaillierBundle();
        int arrayDesc = indexOf(forged, new byte[] {0x75, 0x72, 0x00, 0x02, '[', 'B'});
        assertTrue(arrayDesc >= 0, "the bundle must contain a byte[] (BigInteger magnitude)");
        int lengthAt = indexOf(forged, new byte[] {0x78, 0x70}, arrayDesc) + 2;   // after TC_ENDBLOCKDATA TC_NULL
        int claimed = Integer.MAX_VALUE - 16;
        forged[lengthAt] = (byte) (claimed >>> 24);
        forged[lengthAt + 1] = (byte) (claimed >>> 16);
        forged[lengthAt + 2] = (byte) (claimed >>> 8);
        forged[lengthAt + 3] = (byte) claimed;

        Path file = write(forged);
        FheException e = assertThrows(FheException.class, () -> BlindContext.loadKeys(file.toString()));
        assertInstanceOf(InvalidClassException.class, e.getCause(),
            "the array length must be rejected by the deserialization filter, not discovered by "
                + "allocating it and running out of stream: " + e.getCause());
    }

    // ── helpers ──────────────────────────────────────────────────────────

    private static int indexOf(byte[] haystack, byte[] needle) {
        return indexOf(haystack, needle, 0);
    }

    private static int indexOf(byte[] haystack, byte[] needle, int from) {
        outer:
        for (int i = from; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    /** The contract: success or {@link FheException}; anything else propagates and fails the test. */
    private void assertLoadKeysContract(byte[] bytes) {
        Path file = write(bytes);
        try {
            BlindContext.loadKeys(file.toString());
        } catch (FheException expected) {
            // a rejected file is the correct outcome for most inputs
        } finally {
            BlindContext.clear();
        }
    }

    private byte[] exportedPaillierBundle() throws IOException {
        BlindContext.clear();
        BlindContext.init(new PaillierKeyPair(512));
        Path file = tempDir.resolve("valid.bbk");
        BlindContext.exportKeys(file.toString());
        BlindContext.clear();
        return Files.readAllBytes(file);
    }

    private Path write(byte[] bytes) {
        try {
            Path file = Files.createTempFile(tempDir, "fuzz", ".bbk");
            Files.write(file, bytes);
            return file;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}

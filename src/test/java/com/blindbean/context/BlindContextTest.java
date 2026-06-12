package com.blindbean.context;

import com.blindbean.core.Ciphertext;
import com.blindbean.fhe.FheException;
import com.blindbean.math.PaillierKeyPair;
import com.blindbean.math.PaillierMath;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InvalidClassException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Lifecycle, snapshot/restore, and key import/export tests for {@link BlindContext}.
 * All tests exercise the Paillier paths only, so they run without the native FHE library.
 */
public class BlindContextTest {

    @TempDir
    Path tempDir;

    @AfterEach
    public void teardown() {
        BlindContext.clear();
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────

    @Test
    public void getPaillierAutoInitializesWhenUnset() {
        BlindContext.clear();
        PaillierMath paillier = BlindContext.getPaillier();
        assertNotNull(paillier);
        assertSame(paillier, BlindContext.getPaillier(), "subsequent calls must return the same instance");
    }

    @Test
    public void initWithCustomKeyPairIsUsedByGetPaillier() {
        PaillierKeyPair kp = new PaillierKeyPair(512);
        BlindContext.init(kp);
        assertSame(kp, BlindContext.getPaillier().getKeyPair());
    }

    @Test
    public void clearIsIdempotent() {
        BlindContext.init();
        BlindContext.clear();
        BlindContext.clear(); // second call must be a no-op, not an error
        PaillierMath reinitialized = BlindContext.getPaillier();
        assertNotNull(reinitialized);
    }

    @Test
    public void clearDropsThePaillierInstance() {
        BlindContext.init();
        PaillierMath before = BlindContext.getPaillier();
        BlindContext.clear();
        assertNotSame(before, BlindContext.getPaillier(), "clear() must drop the previous instance");
    }

    @Test
    public void getFheContextWithoutInitThrowsHelpfulException() {
        BlindContext.clear();
        FheException e = assertThrows(FheException.class, BlindContext::getFheContext);
        assertTrue(e.getMessage().contains("initBfv"),
            "error message should point the caller at the init methods");
    }

    // ── Snapshot / restore across threads ─────────────────────────────────

    @Test
    public void snapshotRestorePropagatesPaillierAcrossThreads() throws InterruptedException {
        BlindContext.init();
        PaillierMath original = BlindContext.getPaillier();
        BlindContext.Snapshot snapshot = BlindContext.snapshot();

        AtomicReference<PaillierMath> seenOnOtherThread = new AtomicReference<>();
        Thread worker = new Thread(() -> {
            BlindContext.restore(snapshot);
            seenOnOtherThread.set(BlindContext.getPaillier());
            BlindContext.clear();
        });
        worker.start();
        worker.join();

        assertSame(original, seenOnOtherThread.get(),
            "restore() must install the snapshotted Paillier instance on the new thread");
    }

    @Test
    public void emptySnapshotHasNullFields() {
        BlindContext.clear();
        BlindContext.Snapshot snapshot = BlindContext.snapshot();
        assertNull(snapshot.paillier());
        assertNull(snapshot.fhe());
    }

    // ── Key export / import ───────────────────────────────────────────────

    @Test
    public void paillierKeysSurviveExportAndLoad() throws Exception {
        Path bundleFile = tempDir.resolve("keys.bin");
        BigInteger message = BigInteger.valueOf(123456789L);

        BlindContext.init();
        Ciphertext encrypted = BlindContext.getPaillier().encrypt(message);
        BlindContext.exportKeys(bundleFile.toString());

        BlindContext.clear();
        BlindContext.loadKeys(bundleFile.toString());

        assertEquals(message, BlindContext.getPaillier().decrypt(encrypted),
            "a ciphertext from before export must decrypt after loadKeys");
    }

    @Test
    public void exportKeysWithNoStateThrows() {
        BlindContext.clear();
        Path bundleFile = tempDir.resolve("empty.bin");
        FheException e = assertThrows(FheException.class,
            () -> BlindContext.exportKeys(bundleFile.toString()));
        assertTrue(e.getMessage().contains("No open BlindContext"),
            "the original failure must not be wrapped in a generic export error, got: " + e.getMessage());
    }

    @Test
    public void loadKeysFromMissingFileThrowsFheException() {
        assertThrows(FheException.class,
            () -> BlindContext.loadKeys(tempDir.resolve("does-not-exist.bin").toString()));
    }

    @Test
    public void loadKeysRejectsForeignSerializedClasses() throws Exception {
        Path malicious = tempDir.resolve("gadget.bin");
        try (ObjectOutputStream oos = new ObjectOutputStream(Files.newOutputStream(malicious))) {
            HashMap<String, String> notAKeyBundle = new HashMap<>();
            notAKeyBundle.put("payload", "gadget");
            oos.writeObject(notAKeyBundle);
        }

        FheException e = assertThrows(FheException.class,
            () -> BlindContext.loadKeys(malicious.toString()));
        assertInstanceOf(InvalidClassException.class, e.getCause(),
            "the deserialization filter must reject classes outside the KeyBundle allowlist");
    }
}

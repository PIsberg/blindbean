package se.deversity.blindbean.logging;

import se.deversity.blindbean.context.BlindContext;
import se.deversity.blindbean.context.BlindRotation;
import se.deversity.blindbean.core.Ciphertext;
import se.deversity.blindbean.core.WrongKeyException;
import se.deversity.blindbean.math.PaillierKeyPair;
import se.deversity.blindbean.math.PaillierMath;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.math.BigInteger;
import java.nio.file.Path;
import java.util.List;
import java.util.logging.Level;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * What the logging is allowed to say, and what it must never say.
 *
 * <p>BlindBean logs through {@code System.Logger}, so it adds no logging dependency to a
 * consumer's compile path. With no {@code LoggerFinder} on the path the JDK routes those records
 * to {@code java.util.logging}, which is what {@link LogCapture} attaches to. That is an
 * implementation detail of the JDK default, and it is the reason this suite asserts on captured
 * records rather than on stdout.
 *
 * <p>The first test is the one that earns its keep. {@code KeyBundle.paillierKeyPair} and
 * {@code KeyBundle.nativeFhePayload} carry an {@code @AISecureLogging} OMIT policy, and
 * {@code BlindRotation} is {@code @AIPrivacy}-guarded against logging the decrypted plaintext.
 * Those are declarations; until something executes the paths and reads back every record, they
 * are only a promise. A leak here would not be a cosmetic defect: a plaintext balance in an
 * application log is the disclosure the whole library exists to prevent, and it would be written
 * by the library itself, at DEBUG, on a machine whose logs are probably shipped somewhere central.
 *
 * <p>No {@code @Tag("native")}: everything here is Paillier and lifecycle, so it runs in the Linux
 * fast gate.
 */
class LoggingBehaviourTest {

    /** 512-bit, test-only, for keygen speed. Not a production size. */
    private static final PaillierKeyPair KEYS = new PaillierKeyPair(512);

    /** Distinctive enough that a substring search for it cannot match by chance. */
    private static final BigInteger SECRET = new BigInteger("8675309112233445577");

    private LogCapture logs;

    @BeforeEach
    void installCapture() {
        BlindContext.clear();
        logs = LogCapture.install();
    }

    @AfterEach
    void removeCapture() {
        logs.close();
        BlindContext.clear();
    }

    // ── 1. Nothing secret reaches the log, at any level ───────────────────

    /**
     * Drives the paths that hold secrets in memory, then reads back every captured record at every
     * level and asserts none of them carries the plaintext, the ciphertext, or the modulus.
     *
     * <p>The modulus is checked as well as the plaintext. It is public, so logging it would not be
     * a disclosure, but it is the one field of the key pair a formatter would reach first if
     * anything ever logged a {@code PaillierKeyPair} whole, which is exactly what the OMIT policy
     * forbids. It is the canary for "someone passed the key object to a log call".
     */
    @Test
    void noPlaintextCiphertextOrKeyMaterialIsEverLogged(@TempDir Path tempDir) {
        BlindContext.init(KEYS);
        PaillierMath math = BlindContext.getPaillier();

        Ciphertext ct = math.encrypt(SECRET);
        BigInteger roundTripped = math.decryptSigned(ct);
        Ciphertext sum = math.add(ct, math.encrypt(BigInteger.ONE));

        // The rotation path, which holds the decrypted plaintext in a local while re-encrypting.
        PaillierKeyPair target = new PaillierKeyPair(512);
        try (BlindRotation rotation = BlindRotation.paillier(KEYS, target)) {
            rotation.rotate(ct);
            rotation.commit();
        }

        // The key-serialization path, whose payload and key pair are both OMIT-masked.
        BlindContext.init(KEYS);
        String bundlePath = tempDir.resolve("keys.bundle").toString();
        BlindContext.exportKeys(bundlePath);
        BlindContext.loadKeys(bundlePath);

        String everything = logs.allText();

        assertFalse(everything.contains(SECRET.toString()),
            "the plaintext reached a log record; this is the disclosure the library exists to prevent");
        assertFalse(everything.contains(roundTripped.toString()),
            "the decrypted value reached a log record");
        assertFalse(everything.contains(ct.hexData()),
            "ciphertext bytes reached a log record");
        assertFalse(everything.contains(sum.hexData()),
            "the homomorphic result's ciphertext reached a log record");
        assertFalse(everything.contains(KEYS.getN().toString()),
            "the key modulus reached a log record, which means a key object was passed to a log call");
        assertFalse(everything.contains(target.getN().toString()),
            "the rotation target's key modulus reached a log record");

        // Guards the guard: if nothing was captured, every assertion above passes vacuously.
        assertTrue(logs.records().size() > 5,
            "expected the driven paths to log something; capturing nothing would make this test "
            + "pass without checking anything. Captured: " + logs.records().size());
    }

    // ── 2. INFO stays sparse ──────────────────────────────────────────────

    /**
     * A steady-state encrypt/decrypt loop must produce no INFO at all. INFO is for the things an
     * operator wants to see once, and a per-operation INFO line is how a log becomes unreadable
     * and expensive at exactly the moment it matters.
     */
    @Test
    void steadyStateCryptoIsSilentAtInfo() {
        BlindContext.init(KEYS);
        PaillierMath math = BlindContext.getPaillier();
        logs.clear();

        for (int i = 0; i < 25; i++) {
            math.decryptSigned(math.encrypt(BigInteger.valueOf(i)));
        }

        List<String> info = logs.messagesAt(Level.INFO);
        assertTrue(info.isEmpty(),
            "25 encrypt/decrypt round trips must not log at INFO, got " + info.size() + ": " + info);
    }

    /**
     * Initialising a context is a main event, so it logs exactly one INFO line, and that line
     * carries the vital facts: which key generation is now installed. A line that says only
     * "initialised" costs the same and answers nothing.
     */
    @Test
    void contextInitialisationLogsOneVitalInfoLine() {
        logs.clear();
        BlindContext.init(KEYS);

        List<String> info = logs.messagesAt(Level.INFO);
        assertEquals(1, info.size(), "expected exactly one INFO line for context init, got: " + info);
        assertTrue(info.get(0).contains("Paillier context ready"), info.get(0));
        assertTrue(info.get(0).contains("keyTag="),
            "the INFO line must identify which key generation is installed: " + info.get(0));
    }

    // ── 3. DEBUG tells the story ──────────────────────────────────────────

    /**
     * The same run at DEBUG should let someone reconstruct what happened without a debugger:
     * context taken, ciphertexts rotated with a running count, session closed.
     */
    @Test
    void debugReconstructsTheRotationStory() {
        BlindContext.init(KEYS);
        logs.clear();

        BlindContext.Snapshot snapshot = BlindContext.snapshot();
        BlindContext.restore(snapshot);

        PaillierMath math = BlindContext.getPaillier();
        Ciphertext first = math.encrypt(BigInteger.valueOf(11));
        Ciphertext second = math.encrypt(BigInteger.valueOf(22));

        try (BlindRotation rotation = BlindRotation.paillier(KEYS, new PaillierKeyPair(512))) {
            rotation.rotate(first);
            rotation.rotate(second);
            rotation.commit();
        }

        String debug = String.join("\n", logs.messagesAt(Level.FINE));

        assertTrue(debug.contains("Snapshot taken"), "snapshot missing from the DEBUG story:\n" + debug);
        assertTrue(debug.contains("Restoring snapshot"), "restore missing from the DEBUG story:\n" + debug);
        assertTrue(debug.contains("ciphertext #1"), "first rotation missing from the DEBUG story:\n" + debug);
        assertTrue(debug.contains("ciphertext #2"),
            "the running count must let a reader see how far a rotation got:\n" + debug);
        assertTrue(debug.contains("closed"), "session close missing from the DEBUG story:\n" + debug);
    }

    // ── 4. WARN fires on the two conditions that lose data quietly ────────

    /**
     * A rotation closed without committing leaves rotated values under the target keys while the
     * thread still holds the source keys. {@code close()} succeeds silently, so without a WARNING
     * the operator's only clue is that decryption starts failing later.
     */
    @Test
    void abandoningARotationAfterRotatingWarns() {
        BlindContext.init(KEYS);
        PaillierMath math = BlindContext.getPaillier();
        Ciphertext ct = math.encrypt(BigInteger.valueOf(99));
        logs.clear();

        try (BlindRotation rotation = BlindRotation.paillier(KEYS, new PaillierKeyPair(512))) {
            rotation.rotate(ct);
            // no commit
        }

        List<String> warnings = logs.messagesAt(Level.WARNING);
        assertEquals(1, warnings.size(), "expected exactly one WARNING, got: " + warnings);
        assertTrue(warnings.get(0).contains("WITHOUT commit"), warnings.get(0));
        assertTrue(warnings.get(0).contains("1"),
            "the warning must say how many values are stranded: " + warnings.get(0));
    }

    /** A closed-without-rotating session is routine teardown and must stay quiet. */
    @Test
    void abandoningARotationThatDidNothingIsNotAWarning() {
        BlindContext.init(KEYS);
        logs.clear();

        try (BlindRotation rotation = BlindRotation.paillier(KEYS, new PaillierKeyPair(512))) {
            assertEquals(0, rotation.rotatedCount());
        }

        assertTrue(logs.messagesAt(Level.WARNING).isEmpty(),
            "a rotation that rotated nothing is ordinary teardown, not a warning: "
            + logs.messagesAt(Level.WARNING));
    }

    /**
     * The wrong-key refusal is the false-ACCEPT boundary holding. The caller sees the exception,
     * but an operator watching logs should see it too: in a rotation re-run it is the difference
     * between a refused row and a corrupted one.
     */
    @Test
    void refusingAForeignKeyWarnsAsWellAsThrowing() {
        PaillierMath alice = new PaillierMath(KEYS);
        PaillierMath bob = new PaillierMath(new PaillierKeyPair(512));
        Ciphertext underAlice = alice.encrypt(BigInteger.valueOf(4242));
        logs.clear();

        assertThrows(WrongKeyException.class, () -> bob.decrypt(underAlice));

        List<String> warnings = logs.messagesAt(Level.WARNING);
        assertFalse(warnings.isEmpty(), "the refusal must be visible in the log, not only to the caller");
        assertTrue(warnings.get(0).contains("Refusing to"), warnings.get(0));
        assertTrue(warnings.get(0).contains("rotation re-run"),
            "the warning should name the usual cause, which is what makes it actionable: "
            + warnings.get(0));
    }
}

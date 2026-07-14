package com.example;

import com.blindbean.context.BlindContext;
import com.blindbean.context.BlindRotation;
import com.blindbean.math.PaillierKeyPair;
import com.example.entity.SensorData;
import com.example.entity.SensorDataBlindWrapper;
import com.example.entity.UserAccount;
import com.example.entity.UserAccountBlindWrapper;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Rotating the encryption keys of a live dataset, the way an application would: keep the
 * ciphertexts, swap the keys underneath them.
 *
 * <p>Ciphertexts are bound to the keys that produced them, so rotation means re-encryption.
 * {@link BlindRotation} holds both key generations at once — the plaintext exists only inside
 * {@code rotate()}, and the application keeps running on the old keys until {@code commit()}.
 */
public class KeyRotationTest {

    private static final String KEY_FILE = "rotated_keys.bin";

    @BeforeEach
    public void setup() {
        BlindContext.clear();
    }

    @AfterEach
    public void teardown() throws Exception {
        BlindContext.clear();
        Files.deleteIfExists(Path.of(KEY_FILE));
    }

    /**
     * The everyday case: a table of Paillier-encrypted accounts is re-keyed in a batch, and the
     * new bundle is persisted. Note that nothing here decrypts a balance — the wrapper's
     * generated rotate hook moves the ciphertext across without the plaintext ever surfacing.
     */
    @Test
    public void rotatesAWholeTableOfAccountsOntoFreshKeys() {
        BlindContext.init();

        // A "table" of accounts, encrypted under the keys the app is running on today.
        List<UserAccount> accounts = List.of(new UserAccount(null), new UserAccount(null), new UserAccount(null));
        long[] balances = {1_000L, 25_000L, 7L};
        for (int i = 0; i < accounts.size(); i++) {
            new UserAccountBlindWrapper(accounts.get(i))
                .encryptBalance(BigInteger.valueOf(balances[i]));
        }
        String beforeRotation = accounts.get(0).getBalance();

        // Rotate: new keys, same data.
        PaillierKeyPair nextKeys = new PaillierKeyPair(2048);
        try (BlindRotation rotation = BlindRotation.fromCurrent(nextKeys)) {
            for (UserAccount account : accounts) {
                new UserAccountBlindWrapper(account).rotateBalance(rotation);
                // repository.save(account) — persisting is the application's job
            }
            assertEquals(accounts.size(), rotation.rotatedCount());

            rotation.commit();                  // the app now runs on the new keys
            BlindContext.exportKeys(KEY_FILE);  // retire the old bundle only after this succeeds
        }

        // The stored ciphertext genuinely changed, and the values survived.
        assertNotEquals(beforeRotation, accounts.get(0).getBalance(),
            "the stored ciphertext must have been re-encrypted");
        for (int i = 0; i < accounts.size(); i++) {
            assertEquals(BigInteger.valueOf(balances[i]),
                new UserAccountBlindWrapper(accounts.get(i)).decryptBalance(),
                "balances must be unchanged after rotation");
        }

        // And the new bundle is what a restarted app would load.
        BlindContext.clear();
        BlindContext.loadKeys(KEY_FILE);
        assertEquals(BigInteger.valueOf(25_000L),
            new UserAccountBlindWrapper(accounts.get(1)).decryptBalance(),
            "the exported bundle must decrypt the rotated data after a restart");
    }

    /**
     * BFV rotates the same way, through a fresh native context. An 8192-slot batch survives the
     * move intact, and the rotated ciphertext is still a first-class operand afterwards.
     */
    @Test
    public void rotatesABfvBatchAndKeepsItComputable() {
        BlindContext.initBfv(8192);

        SensorData data = new SensorData();
        SensorDataBlindWrapper wrapper = new SensorDataBlindWrapper(data);

        long[] readings = new long[8192];
        readings[0]    = 500L;
        readings[8191] = 900L;
        wrapper.encryptBatchedReadings(readings);

        try (BlindRotation rotation = BlindRotation.fromCurrentFhe()) {  // fresh SEAL keys, same params
            wrapper.rotateBatchedReadings(rotation);
            rotation.commit();
        }

        // Still computable under the new keys: add a bias across every slot.
        long[] bias = new long[8192];
        java.util.Arrays.fill(bias, 100L);
        wrapper.addBatchedReadings(bias);

        long[] output = wrapper.decryptBatchedReadings();
        assertEquals(600L,  output[0]);
        assertEquals(100L,  output[1]);
        assertEquals(1000L, output[8191]);
    }

    /**
     * Safety net: if the batch blows up halfway, the abandoned session leaves the application on
     * its original keys rather than stranding it with no way to read its own data.
     */
    @Test
    public void anAbandonedRotationLeavesTheAppOnWorkingKeys() {
        BlindContext.init();

        UserAccount account = new UserAccount(null);
        new UserAccountBlindWrapper(account).encryptBalance(BigInteger.valueOf(42L));

        assertThrows(IllegalStateException.class, () -> {
            try (BlindRotation rotation = BlindRotation.fromCurrent(new PaillierKeyPair(2048))) {
                new UserAccountBlindWrapper(account).rotateBalance(rotation);
                throw new IllegalStateException("datastore went away mid-batch");
                // no commit() — the session unwinds
            }
        });

        // The app never swapped keys, so the untouched rows still decrypt.
        UserAccount untouched = new UserAccount(null);
        new UserAccountBlindWrapper(untouched).encryptBalance(BigInteger.valueOf(99L));
        assertEquals(BigInteger.valueOf(99L),
            new UserAccountBlindWrapper(untouched).decryptBalance(),
            "an abandoned rotation must not strand the app without a working key set");
    }
}

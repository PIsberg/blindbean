package com.example;

import com.blindbean.context.BlindContext;
import com.blindbean.core.Ciphertext;
import com.blindbean.annotations.Scheme;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class WalletTest {

    @BeforeEach
    public void setup() {
        // Boot up the encryption core
        BlindContext.init();
    }

    @AfterEach
    public void teardown() {
        BlindContext.clear();
    }

    @Test
    public void testWalletDeposit() {
        // 1. Initial State: Creating the Wallet with 1000 encrypted coins
        Ciphertext initialBalance = BlindContext.getPaillier().encrypt(BigInteger.valueOf(1000));
        Wallet myWallet = new Wallet(initialBalance.hexData());

        // 2. Wrap using generated wrapper from Processor
        WalletBlindWrapper wrapper = new WalletBlindWrapper(myWallet);

        // 3. Deposit 500 encrypted coins without decrypting the wallet!
        Ciphertext deposit = BlindContext.getPaillier().encrypt(BigInteger.valueOf(500));
        wrapper.addFunds(deposit);

        // 4. Verify the new total
        Ciphertext totalBalance = new Ciphertext(myWallet.getFunds(), Scheme.PAILLIER);
        BigInteger decryptedTotal = BlindContext.getPaillier().decrypt(totalBalance);

        // Expecting 1000 + 500 = 1500
        assertEquals(BigInteger.valueOf(1500), decryptedTotal);
    }

    @Test
    public void testEncryptDecryptRoundTrip() {
        // Start with an empty wallet (no initial ciphertext needed)
        Wallet myWallet = new Wallet("");
        WalletBlindWrapper wrapper = new WalletBlindWrapper(myWallet);

        // Encrypt a known value via the generated encryptFunds helper
        wrapper.encryptFunds(BigInteger.valueOf(42));

        // Decrypt it via the generated decryptFunds helper and assert round-trip
        BigInteger recovered = wrapper.decryptFunds();
        assertEquals(BigInteger.valueOf(42), recovered,
            "encryptFunds → decryptFunds round-trip must recover the original plaintext");
    }

    @Test
    public void testEncryptThenAdd() {
        // Use encryptFunds to set an initial balance, then addFunds homomorphically
        Wallet myWallet = new Wallet("");
        WalletBlindWrapper wrapper = new WalletBlindWrapper(myWallet);

        // Encrypt 200 via the generated helper
        wrapper.encryptFunds(BigInteger.valueOf(200));

        // Add 300 homomorphically
        Ciphertext deposit = BlindContext.getPaillier().encrypt(BigInteger.valueOf(300));
        wrapper.addFunds(deposit);

        // Decrypt and verify 200 + 300 = 500
        BigInteger total = wrapper.decryptFunds();
        assertEquals(BigInteger.valueOf(500), total,
            "encryptFunds(200) + addFunds(300) must decrypt to 500");
    }
}

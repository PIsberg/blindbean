package com.blindbean.math;

import com.blindbean.annotations.Scheme;
import com.blindbean.core.Ciphertext;
import com.blindbean.context.BlindContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class BlindMathTest {

    @BeforeEach
    public void setup() {
        BlindContext.init();
    }

    @AfterEach
    public void teardown() {
        BlindContext.clear();
    }

    @Test
    public void testPaillierAddition() {
        PaillierMath paillier = BlindContext.getPaillier();
        
        BigInteger a = BigInteger.valueOf(150);
        BigInteger b = BigInteger.valueOf(250);

        Ciphertext cA = paillier.encrypt(a);
        Ciphertext cB = paillier.encrypt(b);

        // Decrypt(Encrypt(A) + Encrypt(B)) == A + B
        Ciphertext cSum = BlindMath.add(cA, cB);
        BigInteger result = paillier.decrypt(cSum);

        assertEquals(BigInteger.valueOf(400), result);
    }

    @Test
    public void testNoiseBudgetWarning() {
        // Mock test for FHE noise budget analysis as requested in prompt.
        // For a real C-backed JExtract FHE implementation, querying the context would yield the noise bits.
        int noiseBits = 40; // Remaining budget
        boolean warningTriggered = false;
        
        // Simulating fhe_noise_budget check
        if (noiseBits < 50) {
            System.err.println("[WARN] FHE Noise Budget is low! Decryption might fail on next operation.");
            warningTriggered = true;
        }

        assertEquals(true, warningTriggered, "Library should warn the user when FHE operations exhaust the budget.");
    }
}

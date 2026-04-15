package com.example.entity;

import com.blindbean.context.BlindContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class UserAccountTest {

    @BeforeEach
    public void setup() {
        BlindContext.init();
    }

    @AfterEach
    public void teardown() {
        BlindContext.clear();
    }

    @Test
    public void testTransparentMath() {
        // 1. Fetch or Create Entity
        UserAccount user = new UserAccount(null);

        // 2. Transparently Wrap using the Auto-Generated Helper
        UserAccountBlindWrapper wrapper = new UserAccountBlindWrapper(user);

        // 3. Encrypt an initial balance natively
        wrapper.encryptBalance(BigInteger.valueOf(100));

        // 4. Add more to the balance directly via plaintext wrapper!
        wrapper.addBalance(BigInteger.valueOf(500));
        
        // 5. Subtract some from the balance directly!
        wrapper.subBalance(BigInteger.valueOf(100));

        // 6. Decrypt and verify
        BigInteger result = wrapper.decryptBalance();

        // 100 + 500 - 100 = 500
        assertEquals(BigInteger.valueOf(500), result);
    }
}

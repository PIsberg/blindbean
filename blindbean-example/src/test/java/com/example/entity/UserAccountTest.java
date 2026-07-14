package com.example.entity;

import se.deversity.blindbean.context.BlindContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;

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
        wrapper.encryptBalance(new BigDecimal("100.00"));

        // 4. Add more to the balance directly via plaintext wrapper!
        wrapper.addBalance(new BigDecimal("500.50"));
        
        // 5. Subtract some from the balance directly!
        wrapper.subBalance(new BigDecimal("100.25"));

        // 6. Decrypt and verify
        BigDecimal result = wrapper.decryptBalance();

        // 100.00 + 500.50 - 100.25 = 500.25, to the cent. This is why money is a
        // BigDecimal on Paillier and not a double on CKKS.
        assertEquals(new BigDecimal("500.25"), result);
    }
}

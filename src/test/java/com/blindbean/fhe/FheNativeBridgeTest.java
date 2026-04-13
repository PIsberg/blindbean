package com.blindbean.fhe;

import org.junit.jupiter.api.Test;
import java.lang.foreign.MemorySegment;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class FheNativeBridgeTest {

    @Test
    public void testNativeBfvAddition() {
        // Initialize Context
        MemorySegment ctx = FheNativeBridge.fhe_init_bfv(8192);

        // Encrypt Values
        MemorySegment ctA = FheNativeBridge.fhe_encrypt_long(ctx, 100L);
        MemorySegment ctB = FheNativeBridge.fhe_encrypt_long(ctx, 300L);

        // Add
        MemorySegment ctSum = FheNativeBridge.fhe_add(ctx, ctA, ctB);

        // Decrypt
        long sum = FheNativeBridge.fhe_decrypt_long(ctx, ctSum);

        // Assert
        assertEquals(400L, sum);

        // Cleanup
        FheNativeBridge.fhe_destroy_context(ctx);
    }
}

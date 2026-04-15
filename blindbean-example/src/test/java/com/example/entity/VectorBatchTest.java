package com.example.entity;

import com.blindbean.context.BlindContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class VectorBatchTest {

    @BeforeEach
    public void setup() {
        // init BFV context for array batching!
        BlindContext.initBfv(8192);
    }

    @AfterEach
    public void teardown() {
        BlindContext.clear();
    }

    @Test
    public void testSimdBatchingMathematics() {
        SensorData sensor = new SensorData();
        SensorDataBlindWrapper wrapper = new SensorDataBlindWrapper(sensor);

        // Prepare exactly 8192 test readings (the explicit modulus bound)
        long[] initialReadings = new long[8192];
        for (int i = 0; i < 8192; i++) {
            initialReadings[i] = i * 2L; 
        }

        // Native encryption array downcall!
        wrapper.encryptBatchedReadings(initialReadings);

        long[] bias = new long[8192];
        for (int i = 0; i < 8192; i++) {
            bias[i] = 100L; 
        }

        // SIMD batch math! This perfectly adds 100 to all 8192 indices seamlessly on the exact same loop.
        wrapper.addBatchedReadings(bias);
        wrapper.mulBatchedReadings(bias);

        long[] decodedResult = wrapper.decryptBatchedReadings();

        // Ensure length maps symmetrically
        assertEquals(8192, decodedResult.length);

        // Decode first entry: (0 * 2 + 100) * 100 = 10000
        assertEquals(10000L, decodedResult[0]);
        
        // Decode second entry: (1 * 2 + 100) * 100 = 10200
        assertEquals(10200L, decodedResult[1]);

        // Decode last entry: (8191 * 2 + 100) * 100 = 1648200
        assertEquals(1648200L, decodedResult[8191]);
    }
}

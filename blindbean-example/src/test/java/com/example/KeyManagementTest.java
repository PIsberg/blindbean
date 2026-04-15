package com.example;

import com.blindbean.context.BlindContext;
import com.example.entity.SensorData;
import com.example.entity.SensorDataBlindWrapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

public class KeyManagementTest {

    private final String KEY_FILE = "test_persistence.key";

    @BeforeEach
    public void setup() {
        BlindContext.clear();
    }

    @AfterEach
    public void teardown() throws Exception {
        BlindContext.clear();
        Files.deleteIfExists(Path.of(KEY_FILE));
    }

    @Test
    public void testFullLifecycleKeySimulation() {
        // App Start 1
        BlindContext.initBfv(8192);

        SensorData data1 = new SensorData();
        SensorDataBlindWrapper wrapper = new SensorDataBlindWrapper(data1);

        long[] readings = new long[8192];
        readings[0] = 500L;
        readings[8191] = 900L;

        wrapper.encryptBatchedReadings(readings);

        long[] bias = new long[8192];
        for (int i=0; i<8192; i++) bias[i] = 100L;

        wrapper.addBatchedReadings(bias); // modifies ciphertext natively

        // Save Context exactly and halt
        BlindContext.exportKeys(KEY_FILE);
        BlindContext.clear(); 
        // Entire environment simulates memory purge, keys destroyed.

        // App Start 2
        BlindContext.loadKeys(KEY_FILE);

        // Resume interaction with previously encrypted artifact without supplying anything
        SensorDataBlindWrapper resumedWrapper = new SensorDataBlindWrapper(data1);

        long[] output = resumedWrapper.decryptBatchedReadings();

        // Ensure keys mapped back symmetrically to the specific BFV batch context
        assertEquals(600L, output[0]);
        assertEquals(100L, output[1]);
        assertEquals(1000L, output[8191]);
    }
}

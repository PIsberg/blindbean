package com.example;

import com.example.entity.NumericEntity;
import com.example.entity.NumericEntityBlindWrapper;
import com.blindbean.context.BlindContext;
import com.blindbean.fhe.FheContext;
import com.blindbean.annotations.Scheme;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class NumericTypeTest {

    private static FheContext bfv;
    private static FheContext ckks;

    @BeforeAll
    static void setup() {
        bfv = FheContext.bfv(8192);
        ckks = FheContext.ckks(8192, Math.pow(2.0, 40));
        BlindContext.restore(new BlindContext.Snapshot(null, bfv)); // Default FHE context
        // Paillier is initialized by default in BlindContext
    }

    @AfterAll
    static void cleanup() {
        if (bfv != null) bfv.close();
        if (ckks != null) ckks.close();
    }

    @Test
    void testAllNumericTypes() {
        NumericEntity entity = new NumericEntity();
        NumericEntityBlindWrapper wrapper = new NumericEntityBlindWrapper(entity);

        // 1. Byte (Paillier)
        wrapper.encryptByteVal((byte) 42);
        assertEquals((byte) 42, wrapper.decryptByteVal());

        // 2. Short (Paillier)
        wrapper.encryptShortVal((short) 1000);
        assertEquals((short) 1000, wrapper.decryptShortVal());

        // 3. Int (Paillier)
        wrapper.encryptIntVal(123456);
        assertEquals(123456, wrapper.decryptIntVal());

        // 4. Long (BFV)
        wrapper.encryptLongVal(12345L);
        assertEquals(12345L, wrapper.decryptLongVal());

        // 5. Float (CKKS)
        // Note: CKKS needs the CKKS context to be current
        BlindContext.restore(new BlindContext.Snapshot(null, ckks));
        wrapper.encryptFloatVal(3.14f);
        // Compare with epsilon due to CKKS approximation
        assertTrue(Math.abs(3.14f - wrapper.decryptFloatVal()) < 0.01);

        // 6. Double (CKKS)
        wrapper.encryptDoubleVal(2.71828);
        assertTrue(Math.abs(2.71828 - wrapper.decryptDoubleVal()) < 0.0001);
    }

    @Test
    void testIntegralMathAcrossSchemes() {
        NumericEntity entity = new NumericEntity();
        NumericEntityBlindWrapper wrapper = new NumericEntityBlindWrapper(entity);

        // Int (Paillier) addition
        wrapper.encryptIntVal(10);
        wrapper.addIntVal(java.math.BigInteger.valueOf(20));
        assertEquals(30, wrapper.decryptIntVal());

        // Long (BFV) addition
        BlindContext.restore(new BlindContext.Snapshot(null, bfv));
        wrapper.encryptLongVal(100L);
        wrapper.addLongVal(50L);
        assertEquals(150L, wrapper.decryptLongVal());
    }
}

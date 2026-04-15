package com.example.entity;

import com.blindbean.annotations.BlindEntity;
import com.blindbean.annotations.Homomorphic;
import com.blindbean.annotations.Scheme;

@BlindEntity
public class SensorData {
    
    @Homomorphic(scheme = Scheme.BFV, type = long[].class)
    private String batchedReadings; // Ciphertext hex pointing to exactly 8,192 longs under the hood!

    public SensorData() {}

    public String getBatchedReadings() {
        return batchedReadings;
    }

    public void setBatchedReadings(String batchedReadings) {
        this.batchedReadings = batchedReadings;
    }
}

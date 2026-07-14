package com.example.entity;

import se.deversity.blindbean.annotations.BlindEntity;
import se.deversity.blindbean.annotations.Homomorphic;
import se.deversity.blindbean.annotations.Scheme;

import se.deversity.vibetags.annotations.AIPrivacy;

@BlindEntity
public class SensorData {
    
    @AIPrivacy(reason = "Demo entity testing unencrypted data structure bounds. Do not log output.")
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

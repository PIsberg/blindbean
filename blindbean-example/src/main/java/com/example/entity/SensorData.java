package com.example.entity;

import se.deversity.blindbean.annotations.BlindEntity;
import se.deversity.blindbean.annotations.Homomorphic;
import se.deversity.blindbean.annotations.Scheme;

import se.deversity.vibetags.annotations.AIPrivacy;
import se.deversity.vibetags.annotations.AISandboxOnly;
import se.deversity.vibetags.annotations.AISchemaSafe;

/**
 * A batch of sensor readings in a single BFV ciphertext — one slot per reading, all of them
 * added or multiplied in one operation.
 *
 * <p><strong>A slot is not a {@code long}.</strong> The plaintext modulus is ~20 bits, so each slot
 * carries roughly ±516,000 — {@code FheContext.maxSlotValue()} reports the exact limit. Anything
 * larger is refused: SEAL would otherwise reduce it mod t and hand back a plausible wrong number,
 * and one out-of-range reading would corrupt every other slot in the batch. Scale your readings
 * into range before encrypting them.
 */
@BlindEntity
@AIPrivacy(reason = "Sensor readings held as ciphertext — never log the decrypted batch")
@AISchemaSafe
@AISandboxOnly(reason = "Demo fixture for the example walkthrough — production code must never import or copy it")
public class SensorData {

    @Homomorphic(scheme = Scheme.BFV, type = long[].class)
    private String batchedReadings; // hex ciphertext carrying one slot per reading (8,192 at degree 8192)

    public SensorData() {}

    public String getBatchedReadings() {
        return batchedReadings;
    }

    public void setBatchedReadings(String batchedReadings) {
        this.batchedReadings = batchedReadings;
    }
}

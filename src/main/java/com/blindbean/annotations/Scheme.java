package com.blindbean.annotations;

public enum Scheme {
    /**
     * Partially Homomorphic Encryption capable of Addition.
     * Paillier is additive: supports encrypted addition and plaintext multiplication.
     */
    PAILLIER,

    /**
     * Fully Homomorphic Encryption (integer arithmetic) using Microsoft SEAL via FFM.
     * BFV supports exact integer addition, subtraction, and multiplication with SIMD batching.
     */
    BFV,

    /**
     * Fully Homomorphic Encryption (approximate arithmetic) using Microsoft SEAL via FFM.
     * CKKS supports floating-point addition, subtraction, and multiplication with configurable precision.
     */
    CKKS
}

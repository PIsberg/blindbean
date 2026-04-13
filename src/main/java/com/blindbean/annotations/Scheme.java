package com.blindbean.annotations;

public enum Scheme {
    /**
     * Partially Homomorphic Encryption capable of Addition.
     */
    PAILLIER,

    /**
     * Partially Homomorphic Encryption capable of Multiplication.
     */
    ELGAMAL,

    /**
     * Fully Homomorphic Encryption using native jextract bridge.
     */
    BFV,
    CKKS
}

package com.blindbean.math;

import com.blindbean.core.Ciphertext;

public class BlindMath {
    
    public static Ciphertext add(Ciphertext a, Ciphertext b) {
        // Transparent dispatch
        return switch (a.scheme()) {
            case PAILLIER -> com.blindbean.context.BlindContext.getPaillier().add(a, b);
            case ELGAMAL, BFV, CKKS -> throw new UnsupportedOperationException("Addition not yet implemented for: " + a.scheme());
        };
    }
}

package com.blindbean.math;

import com.blindbean.core.Ciphertext;
import com.blindbean.context.BlindContext;
import com.blindbean.fhe.FheCiphertextNative;
import com.blindbean.fhe.FheContext;

public class BlindMath {
    
    /**
     * Homomorphically adds two ciphertexts, dispatching to the correct backend
     * based on the encryption scheme.
     */
    public static Ciphertext add(Ciphertext a, Ciphertext b) {
        if (a.scheme() != b.scheme()) {
            throw new IllegalArgumentException("Cannot add ciphertexts of different schemes: " + a.scheme() + " vs " + b.scheme());
        }
        return switch (a.scheme()) {
            case PAILLIER -> BlindContext.getPaillier().add(a, b);
            case BFV, CKKS -> fheAdd(a, b);
            case ELGAMAL -> throw new UnsupportedOperationException("Addition not supported for ElGamal (multiplicative scheme)");
        };
    }

    /**
     * Homomorphically multiplies two ciphertexts.
     * Only supported for FHE schemes (BFV, CKKS).
     */
    public static Ciphertext multiply(Ciphertext a, Ciphertext b) {
        if (a.scheme() != b.scheme()) {
            throw new IllegalArgumentException("Cannot multiply ciphertexts of different schemes: " + a.scheme() + " vs " + b.scheme());
        }
        return switch (a.scheme()) {
            case BFV, CKKS -> fheMultiply(a, b);
            case PAILLIER -> throw new UnsupportedOperationException("Multiplication not supported for Paillier (additive scheme)");
            case ELGAMAL -> throw new UnsupportedOperationException("Multiplication not yet implemented for ElGamal");
        };
    }

    // ── Private FHE dispatch ──────────────────────────────────

    private static Ciphertext fheAdd(Ciphertext a, Ciphertext b) {
        FheContext ctx = BlindContext.getFheContext();
        try (var ctA = FheCiphertextNative.fromBlindCiphertext(ctx, a);
             var ctB = FheCiphertextNative.fromBlindCiphertext(ctx, b)) {

            var resultHandle = ctx.add(ctA.handle(), ctB.handle());
            try (var ctResult = new FheCiphertextNative(resultHandle, ctx)) {
                return ctResult.toBlindCiphertext();
            }
        }
    }

    private static Ciphertext fheMultiply(Ciphertext a, Ciphertext b) {
        FheContext ctx = BlindContext.getFheContext();
        try (var ctA = FheCiphertextNative.fromBlindCiphertext(ctx, a);
             var ctB = FheCiphertextNative.fromBlindCiphertext(ctx, b)) {

            var resultHandle = ctx.multiply(ctA.handle(), ctB.handle());
            try (var ctResult = new FheCiphertextNative(resultHandle, ctx)) {
                return ctResult.toBlindCiphertext();
            }
        }
    }
}

package com.blindbean.context;

import com.blindbean.annotations.Scheme;
import com.blindbean.math.PaillierKeyPair;
import java.io.Serializable;

/**
 * Encapsulates the entire cryptographic state of BlindContext.
 * Securely holds Paillier KeyPair instances natively and massive 
 * native FHE binary arrays encoding Microsoft SEAL engine data.
 */
public class KeyBundle implements Serializable {
    private static final long serialVersionUID = 1L;

    private final PaillierKeyPair paillierKeyPair;
    
    // FHE Parameters
    private final Scheme fheScheme;
    private final int polyModulusDegree;
    private final double scale;
    private final byte[] nativeFhePayload;

    public KeyBundle(PaillierKeyPair paillierKeyPair, Scheme fheScheme, int polyModulusDegree, double scale, byte[] nativeFhePayload) {
        this.paillierKeyPair = paillierKeyPair;
        this.fheScheme = fheScheme;
        this.polyModulusDegree = polyModulusDegree;
        this.scale = scale;
        this.nativeFhePayload = nativeFhePayload;
    }

    public PaillierKeyPair getPaillierKeyPair() {
        return paillierKeyPair;
    }

    public Scheme getFheScheme() {
        return fheScheme;
    }

    public int getPolyModulusDegree() {
        return polyModulusDegree;
    }

    public double getScale() {
        return scale;
    }

    public byte[] getNativeFhePayload() {
        return nativeFhePayload;
    }
}

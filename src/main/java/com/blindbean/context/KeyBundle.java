package com.blindbean.context;

import com.blindbean.annotations.Scheme;
import com.blindbean.math.PaillierKeyPair;
import java.io.Serializable;

import se.deversity.vibetags.annotations.AILocked;
import se.deversity.vibetags.annotations.AIPrivacy;
import se.deversity.vibetags.annotations.AISchemaSafe;

/**
 * Encapsulates the entire cryptographic state of BlindContext.
 * Securely holds Paillier KeyPair instances natively and massive
 * native FHE binary arrays encoding Microsoft SEAL engine data.
 */
@AIPrivacy(reason = "Contains serialized Paillier private key material and SEAL key bytes — never log, transmit in plaintext, or expose field values in suggestions or test fixtures")
@AISchemaSafe
public class KeyBundle implements Serializable {
    @AILocked(reason = "Serialization UID — altering this invalidates all persisted key bundles and breaks key import/export across versions")
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

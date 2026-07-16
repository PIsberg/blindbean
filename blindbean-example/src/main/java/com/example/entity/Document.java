package com.example.entity;

import se.deversity.blindbean.annotations.BlindEntity;
import se.deversity.blindbean.annotations.Homomorphic;
import se.deversity.blindbean.annotations.Scheme;

import se.deversity.vibetags.annotations.AIPrivacy;
import se.deversity.vibetags.annotations.AISandboxOnly;
import se.deversity.vibetags.annotations.AISchemaSafe;

@BlindEntity
@AIPrivacy(reason = "Holds document text and a verification flag as ciphertext — never log the"
                  + "decrypted text")
@AISchemaSafe
@AISandboxOnly(reason = "Demo fixture for the example walkthrough — production code must never import or copy it")
public class Document {
    @Homomorphic(scheme = Scheme.PAILLIER, type = String.class)
    private String text; // Stored as a Hex-encoded Ciphertext string
    
    @Homomorphic(scheme = Scheme.PAILLIER, type = boolean.class)
    private String verified; 

    public Document() {
    }

    public String getText() {
        return text;
    }

    public void setText(String text) {
        this.text = text;
    }

    public String getVerified() {
        return verified;
    }

    public void setVerified(String verified) {
        this.verified = verified;
    }
}

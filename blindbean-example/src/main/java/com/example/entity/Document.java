package com.example.entity;

import com.blindbean.annotations.BlindEntity;
import com.blindbean.annotations.Homomorphic;
import com.blindbean.annotations.Scheme;

@BlindEntity
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

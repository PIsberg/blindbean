package com.example;

import se.deversity.blindbean.annotations.BlindEntity;
import se.deversity.blindbean.annotations.Homomorphic;
import se.deversity.blindbean.annotations.Scheme;

import se.deversity.vibetags.annotations.AIPrivacy;
import se.deversity.vibetags.annotations.AISchemaSafe;

@BlindEntity
@AIPrivacy(reason = "Holds wallet funds as ciphertext — never log the decrypted balance")
@AISchemaSafe
public class Wallet {
    
    // Encrypted directly transparently via BlindBean annotations!
    @Homomorphic(scheme = Scheme.PAILLIER)
    private String funds; // Stored natively as Hex encoded string

    public Wallet(String initialFunds) {
        this.funds = initialFunds;
    }

    public String getFunds() {
        return funds;
    }

    public void setFunds(String funds) {
        this.funds = funds;
    }
}

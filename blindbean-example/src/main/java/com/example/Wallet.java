package com.example;

import com.blindbean.annotations.BlindEntity;
import com.blindbean.annotations.Homomorphic;
import com.blindbean.annotations.Scheme;

@BlindEntity
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

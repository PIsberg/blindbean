package com.example.entity;

import se.deversity.blindbean.annotations.BlindEntity;
import se.deversity.blindbean.annotations.Homomorphic;
import se.deversity.blindbean.annotations.Scheme;

@BlindEntity
public class UserAccount {
    @Homomorphic(scheme = Scheme.PAILLIER)
    private String balance; // Stored as a Hex-encoded Ciphertext string

    public UserAccount(String balance) {
        this.balance = balance;
    }

    public String getBalance() {
        return balance;
    }

    public void setBalance(String balance) {
        this.balance = balance;
    }
}

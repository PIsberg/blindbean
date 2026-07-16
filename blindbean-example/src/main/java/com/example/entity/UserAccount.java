package com.example.entity;

import se.deversity.blindbean.annotations.BlindEntity;
import se.deversity.blindbean.annotations.Homomorphic;
import se.deversity.blindbean.annotations.Scheme;

import se.deversity.vibetags.annotations.AIPrivacy;
import se.deversity.vibetags.annotations.AISandboxOnly;
import se.deversity.vibetags.annotations.AISchemaSafe;

/**
 * An account balance held encrypted — the canonical "compute on money you cannot read" case.
 *
 * <p>Money is a {@code BigDecimal} on Paillier, not a {@code BigInteger} and emphatically not CKKS.
 * Paillier stores it as the unscaled integer at a fixed scale, so 19.99 + 0.01 is exactly 20.00;
 * CKKS is approximate and would eventually be off by a fraction of a cent. The scale is part of the
 * storage format — change it and every balance already written decodes at the wrong magnitude.
 */
@BlindEntity
@AIPrivacy(reason = "Holds an account balance as ciphertext — never log the decrypted value, and "
                  + "never put a real balance in a fixture")
@AISchemaSafe
@AISandboxOnly(reason = "Demo fixture for the example walkthrough — production code must never import or copy it")
public class UserAccount {

    @Homomorphic(scheme = Scheme.PAILLIER, type = java.math.BigDecimal.class, scale = 2)
    private String balance; // hex ciphertext of the unscaled amount, NOT a number

    public UserAccount() {}

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

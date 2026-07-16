package com.example.entity;

import se.deversity.blindbean.annotations.BlindEntity;
import se.deversity.blindbean.annotations.Homomorphic;
import se.deversity.blindbean.annotations.Scheme;

import se.deversity.vibetags.annotations.AIPrivacy;
import se.deversity.vibetags.annotations.AISandboxOnly;
import se.deversity.vibetags.annotations.AISchemaSafe;

/**
 * Example entity with {@code async = true} demonstrating parallel fan-out encryption
 * of multiple financial fields via Java 26 virtual threads.
 */
@BlindEntity(async = true)
@AIPrivacy(reason = "Holds a cash balance and holdings as ciphertext — never log decrypted"
                  + "values, and never put a real portfolio in a fixture")
@AISchemaSafe
@AISandboxOnly(reason = "Demo fixture for the example walkthrough — production code must never import or copy it")
public class Portfolio {

    @Homomorphic(scheme = Scheme.PAILLIER)
    private String cashBalance;

    @Homomorphic(scheme = Scheme.PAILLIER)
    private String equityValue;

    @Homomorphic(scheme = Scheme.PAILLIER)
    private String bondValue;

    @Homomorphic(scheme = Scheme.PAILLIER)
    private String realEstateValue;

    public Portfolio() {}

    public String getCashBalance()    { return cashBalance; }
    public void   setCashBalance(String v)    { this.cashBalance = v; }

    public String getEquityValue()    { return equityValue; }
    public void   setEquityValue(String v)    { this.equityValue = v; }

    public String getBondValue()      { return bondValue; }
    public void   setBondValue(String v)      { this.bondValue = v; }

    public String getRealEstateValue() { return realEstateValue; }
    public void   setRealEstateValue(String v) { this.realEstateValue = v; }
}

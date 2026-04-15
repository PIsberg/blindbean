package com.example.entity;

import com.blindbean.annotations.BlindEntity;
import com.blindbean.annotations.Homomorphic;
import com.blindbean.annotations.Scheme;

/**
 * Example entity with {@code async = true} demonstrating parallel fan-out encryption
 * of multiple financial fields via Java 26 virtual threads.
 */
@BlindEntity(async = true)
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

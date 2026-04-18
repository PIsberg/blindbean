package com.example.entity;

import com.blindbean.annotations.BlindEntity;
import com.blindbean.annotations.Homomorphic;
import com.blindbean.annotations.Scheme;

@BlindEntity
public class NumericEntity {

    @Homomorphic(type = byte.class, scheme = Scheme.PAILLIER)
    private String byteVal;

    @Homomorphic(type = short.class, scheme = Scheme.PAILLIER)
    private String shortVal;

    @Homomorphic(type = int.class, scheme = Scheme.PAILLIER)
    private String intVal;

    @Homomorphic(type = long.class, scheme = Scheme.BFV)
    private String longVal;

    @Homomorphic(type = float.class, scheme = Scheme.CKKS)
    private String floatVal;

    @Homomorphic(type = double.class, scheme = Scheme.CKKS)
    private String doubleVal;

    // Getters and setters (required by processor)

    public String getByteVal() { return byteVal; }
    public void setByteVal(String byteVal) { this.byteVal = byteVal; }

    public String getShortVal() { return shortVal; }
    public void setShortVal(String shortVal) { this.shortVal = shortVal; }

    public String getIntVal() { return intVal; }
    public void setIntVal(String intVal) { this.intVal = intVal; }

    public String getLongVal() { return longVal; }
    public void setLongVal(String longVal) { this.longVal = longVal; }

    public String getFloatVal() { return floatVal; }
    public void setFloatVal(String floatVal) { this.floatVal = floatVal; }

    public String getDoubleVal() { return doubleVal; }
    public void setDoubleVal(String doubleVal) { this.doubleVal = doubleVal; }
}

package com.example.entity;

import se.deversity.blindbean.annotations.BlindEntity;
import se.deversity.blindbean.annotations.Homomorphic;
import se.deversity.blindbean.annotations.Scheme;

import se.deversity.vibetags.annotations.AIPrivacy;
import se.deversity.vibetags.annotations.AISchemaSafe;

/** One field per newly supported type — the consumer's-eye view of the type surface. */
@BlindEntity
@AIPrivacy(reason = "Carries a price, an opaque blob and timestamps as ciphertext — never log"
                  + "the decrypted values")
@AISchemaSafe
public class TypeZoo {

    // Exact decimal money. Paillier, fixed scale — CKKS could hold it, but only approximately.
    @Homomorphic(scheme = Scheme.PAILLIER, type = java.math.BigDecimal.class, scale = 2)
    private String price;

    // Opaque bytes. No arithmetic is meaningful on a blob.
    @Homomorphic(scheme = Scheme.PAILLIER, type = byte[].class)
    private String blob;

    // Points in time: no arithmetic (Tuesday + Thursday is not a date).
    @Homomorphic(scheme = Scheme.PAILLIER, type = java.time.Instant.class)
    private String seenAt;

    @Homomorphic(scheme = Scheme.PAILLIER, type = java.time.LocalDate.class)
    private String bornOn;

    // A quantity: adds fine.
    @Homomorphic(scheme = Scheme.PAILLIER, type = java.time.Duration.class)
    private String uptime;

    // Integer vectors — BFV slots.
    @Homomorphic(scheme = Scheme.BFV, type = int[].class)
    private String counters;

    @Homomorphic(scheme = Scheme.BFV, type = short[].class)
    private String flags;

    // Real vectors — CKKS, which is what the scheme is actually for.
    @Homomorphic(scheme = Scheme.CKKS, type = double[].class)
    private String signal;

    @Homomorphic(scheme = Scheme.CKKS, type = float[].class)
    private String weights;

    // Boxed scalar — nullable.
    @Homomorphic(scheme = Scheme.PAILLIER, type = Long.class)
    private String optionalCount;

    public String getPrice() { return price; }
    public void setPrice(String v) { this.price = v; }
    public String getBlob() { return blob; }
    public void setBlob(String v) { this.blob = v; }
    public String getSeenAt() { return seenAt; }
    public void setSeenAt(String v) { this.seenAt = v; }
    public String getBornOn() { return bornOn; }
    public void setBornOn(String v) { this.bornOn = v; }
    public String getUptime() { return uptime; }
    public void setUptime(String v) { this.uptime = v; }
    public String getCounters() { return counters; }
    public void setCounters(String v) { this.counters = v; }
    public String getFlags() { return flags; }
    public void setFlags(String v) { this.flags = v; }
    public String getSignal() { return signal; }
    public void setSignal(String v) { this.signal = v; }
    public String getWeights() { return weights; }
    public void setWeights(String v) { this.weights = v; }
    public String getOptionalCount() { return optionalCount; }
    public void setOptionalCount(String v) { this.optionalCount = v; }
}

package com.example.entity;

import se.deversity.blindbean.annotations.BlindEntity;
import se.deversity.blindbean.annotations.BlindNested;
import se.deversity.blindbean.annotations.Homomorphic;
import se.deversity.blindbean.annotations.Scheme;

import se.deversity.vibetags.annotations.AIPrivacy;
import se.deversity.vibetags.annotations.AISchemaSafe;

/**
 * Composition: an order that owns an encrypted total AND a customer whose balance is encrypted
 * under the customer's own field.
 *
 * <p>Without {@code @BlindNested} you had to reach through the object graph and wrap the inner
 * entity by hand at every call site — exactly the boilerplate the annotations exist to remove.
 * The generated {@code customer()} hands back a {@code UserAccountBlindWrapper}, so the whole of
 * that entity's API is reachable through the order.
 */
@BlindEntity
@AIPrivacy(reason = "Holds an order total as ciphertext and owns an account whose balance is "
                  + "encrypted — never log decrypted values")
@AISchemaSafe
public class Order {

    @Homomorphic(scheme = Scheme.PAILLIER, type = java.math.BigDecimal.class, scale = 2)
    private String total;

    @BlindNested
    private UserAccount customer;

    public Order() {}

    public String getTotal() { return total; }
    public void setTotal(String total) { this.total = total; }

    public UserAccount getCustomer() { return customer; }
    public void setCustomer(UserAccount customer) { this.customer = customer; }
}

package com.example.entity;

import se.deversity.blindbean.context.BlindContext;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/** Reaching through one entity into another's encrypted fields. */
public class NestedEntityTest {

    @BeforeEach
    void setup() { BlindContext.init(); }

    @AfterEach
    void teardown() { BlindContext.clear(); }

    @Test
    void theOrderReachesIntoItsCustomersEncryptedBalance() {
        UserAccount customer = new UserAccount();
        Order order = new Order();
        order.setCustomer(customer);

        var w = new OrderBlindWrapper(order);

        w.encryptTotal(new BigDecimal("19.99"));
        w.customer().encryptBalance(new BigDecimal("100.00"));

        // Debit the customer for the order, without any of it leaving ciphertext.
        w.customer().subBalance(new BigDecimal("19.99"));

        assertEquals(new BigDecimal("19.99"), w.decryptTotal());
        assertEquals(new BigDecimal("80.01"), w.customer().decryptBalance());
    }

    @Test
    void theNestedEntityIsReallyTheSameObject() {
        UserAccount customer = new UserAccount();
        Order order = new Order();
        order.setCustomer(customer);

        new OrderBlindWrapper(order).customer().encryptBalance(new BigDecimal("5.00"));

        // The wrapper writes through to the entity we handed it, not to a copy — otherwise the
        // ciphertext would be stranded inside a temporary and never persisted.
        assertEquals(new BigDecimal("5.00"),
            new UserAccountBlindWrapper(customer).decryptBalance());
    }

    @Test
    void aNullNestedEntityYieldsANullWrapperNotAnNpe() {
        Order order = new Order();     // no customer set
        assertNull(new OrderBlindWrapper(order).customer(),
            "a null nested entity must surface as null here, not as an NPE several frames deep");
    }
}

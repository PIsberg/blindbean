package com.example.entity;

import com.blindbean.async.BlindAsync;
import com.blindbean.context.BlindContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Demonstrates parallel fan-out encryption of all four Portfolio fields on virtual threads,
 * followed by individual async decryption and a round-trip assertion.
 */
public class PortfolioAsyncTest {

    @BeforeEach
    public void setup() {
        BlindContext.init();
        BlindAsync.shutdown(); // clean executor state before each test
    }

    @AfterEach
    public void teardown() {
        BlindAsync.shutdown();
        BlindContext.clear();
    }

    @Test
    public void parallelEncryptThenAsyncDecryptRoundTrip() throws Exception {
        Portfolio portfolio = new Portfolio();
        PortfolioBlindWrapper wrapper = new PortfolioBlindWrapper(portfolio);

        // Fan-out: encrypt all four fields in parallel on virtual threads
        CompletableFuture.allOf(
            wrapper.encryptCashBalanceAsync(BigInteger.valueOf(10_000)),
            wrapper.encryptEquityValueAsync(BigInteger.valueOf(50_000)),
            wrapper.encryptBondValueAsync(BigInteger.valueOf(25_000)),
            wrapper.encryptRealEstateValueAsync(BigInteger.valueOf(150_000))
        ).get();

        // All fields must now hold non-null ciphertext
        assertEquals(BigInteger.valueOf(10_000),  wrapper.decryptCashBalance());
        assertEquals(BigInteger.valueOf(50_000),  wrapper.decryptEquityValue());
        assertEquals(BigInteger.valueOf(25_000),  wrapper.decryptBondValue());
        assertEquals(BigInteger.valueOf(150_000), wrapper.decryptRealEstateValue());
    }

    @Test
    public void asyncAddAccumulatesCorrectly() throws Exception {
        Portfolio portfolio = new Portfolio();
        PortfolioBlindWrapper wrapper = new PortfolioBlindWrapper(portfolio);

        wrapper.encryptCashBalance(BigInteger.valueOf(1_000));

        // Sequential async additions
        wrapper.addCashBalanceAsync(BigInteger.valueOf(500)).get();
        wrapper.addCashBalanceAsync(BigInteger.valueOf(500)).get();

        assertEquals(BigInteger.valueOf(2_000), wrapper.decryptCashBalance());
    }

    @Test
    public void asyncDecryptReturnsFuture() throws Exception {
        Portfolio portfolio = new Portfolio();
        PortfolioBlindWrapper wrapper = new PortfolioBlindWrapper(portfolio);

        wrapper.encryptEquityValue(BigInteger.valueOf(99_999));

        BigInteger result = wrapper.decryptEquityValueAsync().get();
        assertEquals(BigInteger.valueOf(99_999), result);
    }

    @Test
    public void parallelEncryptRunsOnVirtualThreads() throws Exception {
        Portfolio portfolio = new Portfolio();
        PortfolioBlindWrapper wrapper = new PortfolioBlindWrapper(portfolio);

        java.util.concurrent.CopyOnWriteArrayList<Boolean> isVirtuals =
                new java.util.concurrent.CopyOnWriteArrayList<>();

        CompletableFuture.allOf(
            BlindAsync.runAsync(() -> {
                isVirtuals.add(Thread.currentThread().isVirtual());
                wrapper.encryptCashBalance(BigInteger.valueOf(1));
            }),
            BlindAsync.runAsync(() -> {
                isVirtuals.add(Thread.currentThread().isVirtual());
                wrapper.encryptEquityValue(BigInteger.valueOf(2));
            })
        ).get();

        isVirtuals.forEach(v -> assertTrue(v.booleanValue(), "Expected virtual thread"));
    }
}

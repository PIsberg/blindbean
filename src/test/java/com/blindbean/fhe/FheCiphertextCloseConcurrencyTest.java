package com.blindbean.fhe;

import se.deversity.asynctest.AsyncTest;
import se.deversity.asynctest.BeforeEachInvocation;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Concurrent-close stress for {@link FheCiphertextNative}.
 *
 * <p>close() must hand the handle to the native allocator exactly once. A non-atomic test-and-set
 * lets several threads through the guard at once and double-frees the SEAL ciphertext, corrupting
 * the native heap. Every thread in a round races to close the <em>same</em> ciphertext;
 * {@code @BeforeEachInvocation} mints a fresh one per round so each round is a real race rather
 * than a no-op against an already-freed handle.
 */
class FheCiphertextCloseConcurrencyTest {

    private FheContext ctx;
    private volatile FheCiphertextNative shared;

    @BeforeEach
    void setup() {
        ctx = FheContext.bfv(4096);
    }

    @AfterEach
    void teardown() {
        if (ctx != null) {
            ctx.close();
        }
    }

    @BeforeEachInvocation
    void freshCiphertext() {
        shared = new FheCiphertextNative(ctx.encryptLong(7L), ctx);
    }

    @AsyncTest(
        threads = 16,
        invocations = 50,
        detectRaceConditions = true,
        detectAtomicityViolations = true,
        detectResourceLeaks = true,
        timeoutMs = 30000
    )
    void concurrentCloseFreesTheHandleExactlyOnce() {
        shared.close();

        // The handle is gone: further use is rejected rather than touching freed memory.
        assertThrows(FheException.class, shared::handle);
    }
}

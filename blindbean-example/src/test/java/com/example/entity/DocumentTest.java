package com.example.entity;

import com.blindbean.context.BlindContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DocumentTest {

    @BeforeEach
    public void setup() {
        BlindContext.init();
    }

    @AfterEach
    public void teardown() {
        BlindContext.clear();
    }

    @Test
    public void testStringAndBooleanHomomorphicStorage() {
        Document doc = new Document();
        DocumentBlindWrapper wrapper = new DocumentBlindWrapper(doc);

        // 1. Encrypt complex datatypes natively
        wrapper.encryptText("Top secret message");
        wrapper.encryptVerified(true);

        // 2. The underlying entity now holds Paillier Ciphertext hex strings
        assertTrue(doc.getText().length() > 50);
        assertTrue(doc.getVerified().length() > 50);

        // 3. Decrypt and verify types align
        String text = wrapper.decryptText();
        boolean verified = wrapper.decryptVerified();

        assertEquals("Top secret message", text);
        assertTrue(verified);
    }
}

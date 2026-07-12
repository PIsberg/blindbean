package com.blindbean.fhe;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for FheContext factory behavior and the guided native-load
 * diagnostics ({@link FheContext#nativeLoadGuidance(Throwable)}).
 * The happy-path native operations are covered by FheNativeBridgeTest;
 * this class focuses on the first-run failure experience.
 */
public class FheContextTest {

    private static final String PROP = "blindbean.native.path";
    private String savedPath;

    @AfterEach
    void restoreProperty() {
        if (savedPath != null) {
            System.setProperty(PROP, savedPath);
            savedPath = null;
        }
    }

    private void stashProperty() {
        savedPath = System.getProperty(PROP);
    }

    @Test
    public void guidanceNamesTheSystemPropertyWhenUnset() {
        stashProperty();
        System.clearProperty(PROP);
        try {
            String msg = FheContext.nativeLoadGuidance(new UnsatisfiedLinkError("no blindbean_fhe in java.library.path"));
            assertTrue(msg.contains("blindbean.native.path"), "must name the property to set");
            assertTrue(msg.contains("NOT set"), "must say the property is missing");
            assertTrue(msg.contains("-Dblindbean.native.path="), "must show the exact fix flag");
            assertTrue(msg.contains("cmake"), "must include the one-time native build command");
            assertTrue(msg.contains("no blindbean_fhe"), "must preserve the underlying error");
        } finally {
            if (savedPath != null) System.setProperty(PROP, savedPath);
        }
    }

    @Test
    public void guidanceEchoesTheConfiguredPathWhenSet() {
        stashProperty();
        System.setProperty(PROP, "/some/wrong/dir");
        String msg = FheContext.nativeLoadGuidance(new UnsatisfiedLinkError("boom"));
        assertTrue(msg.contains("/some/wrong/dir"), "must echo where it looked");
        assertTrue(msg.contains("verify the library exists"), "must tell the user what to check");
    }

    @Test
    public void guidanceMentionsReleaseSubdirOnWindows() {
        stashProperty();
        System.setProperty(PROP, "build-native");
        String msg = FheContext.nativeLoadGuidance(null);
        if (System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT).contains("win")) {
            assertTrue(msg.contains("Release/"), "Windows guidance must mention the MSVC Release/ subdir");
        }
        // Null cause must not blow up or append an 'Underlying error' line
        assertFalse(msg.contains("Underlying error"));
    }

    @Test
    public void guidanceIncludesOsAndArch() {
        stashProperty();
        String msg = FheContext.nativeLoadGuidance(new NoClassDefFoundError("FheNativeBridge"));
        assertTrue(msg.contains(System.getProperty("os.name")), "must state the detected OS");
        assertTrue(msg.contains(System.getProperty("os.arch")), "must state the detected arch");
    }
}

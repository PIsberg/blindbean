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

    @Test
    public void guidanceTreatsBlankPropertyAsUnset() {
        stashProperty();
        System.setProperty(PROP, "   ");
        String msg = FheContext.nativeLoadGuidance(new UnsatisfiedLinkError("x"));
        assertTrue(msg.contains("NOT set"), "a blank property must be treated as missing");
    }

    @Test
    public void initNativeConvertsUnsatisfiedLinkErrorToGuidedFheException() {
        stashProperty();
        UnsatisfiedLinkError boom = new UnsatisfiedLinkError("no blindbean_fhe found");
        FheException ex = assertThrows(FheException.class,
            () -> FheContext.initNative(() -> { throw boom; }));
        assertSame(boom, ex.getCause(), "original linkage error must be preserved as the cause");
        assertTrue(ex.getMessage().contains("blindbean.native.path"), "message must be the guided one");
        assertTrue(ex.getMessage().contains("no blindbean_fhe found"), "underlying error must be echoed");
    }

    @Test
    public void initNativeConvertsInitializerErrorToGuidedFheException() {
        stashProperty();
        ExceptionInInitializerError boom = new ExceptionInInitializerError("static init failed");
        FheException ex = assertThrows(FheException.class,
            () -> FheContext.initNative(() -> { throw boom; }));
        assertSame(boom, ex.getCause());
        assertTrue(ex.getMessage().contains("could not load the native FHE library"));
    }

    @Test
    public void initNativePassesThroughOnSuccess() {
        stashProperty();
        var segment = java.lang.foreign.MemorySegment.NULL;
        assertSame(segment, FheContext.initNative(() -> segment), "successful init must return the handle untouched");
    }
}

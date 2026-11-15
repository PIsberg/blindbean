package se.deversity.blindbean.fhe;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Where the {@code blindbean_fhe} native library may be loaded from (issue #254, CWE-427).
 * <p>
 * Only the operator-set {@code blindbean.native.path} and the absolute entries of
 * {@code java.library.path} count. A library sitting in the process working directory must never
 * be picked up, whether through BlindBean's own search or through a relative
 * {@code java.library.path} entry (the JDK's Windows default ends in {@code "."}), and a configured
 * directory that lacks the library must fail rather than fall through.
 * <p>
 * No test here needs the real library: the planted files are garbage, so loading one would fail
 * with an {@link UnsatisfiedLinkError} that names it, which is exactly what the assertions rule out.
 */
class NativeLibraryLocatorTest {

    private static final String LIB_FILE = System.mapLibraryName("blindbean_fhe");

    @Test
    void configuredDirectoryHoldingTheLibraryIsUsed(@TempDir Path dir) throws IOException {
        Path library = Files.writeString(dir.resolve(LIB_FILE), "not a real library");

        Path located = NativeLibraryLocator.locate(dir.toString(), "");

        assertEquals(library.toAbsolutePath(), located);
    }

    @Test
    void configuredDirectoryWithoutTheLibraryFailsInsteadOfFallingThrough(@TempDir Path dir) {
        FheException ex = assertThrows(FheException.class,
                () -> NativeLibraryLocator.locate(dir.toString(), ""));

        assertTrue(ex.getMessage().contains("blindbean.native.path"), ex.getMessage());
        assertTrue(ex.getMessage().contains(dir.toString()), "must name the directory searched: " + ex.getMessage());
    }

    @Test
    void configuredPathThatDoesNotExistFails(@TempDir Path dir) {
        String missing = dir.resolve("no-such-dir").toString();

        FheException ex = assertThrows(FheException.class, () -> NativeLibraryLocator.locate(missing, ""));

        assertTrue(ex.getMessage().contains(missing), ex.getMessage());
    }

    @Test
    void unsetPropertyUsesTheFirstAbsoluteJavaLibraryPathEntryHoldingTheLibrary(
            @TempDir Path empty, @TempDir Path holding) throws IOException {
        Path library = Files.writeString(holding.resolve(LIB_FILE), "not a real library");
        String libraryPath = empty + File.pathSeparator + holding;

        assertEquals(library.toAbsolutePath(), NativeLibraryLocator.locate(null, libraryPath));
        assertEquals(library.toAbsolutePath(), NativeLibraryLocator.locate("  ", libraryPath));
    }

    @Test
    void unsetPropertyWithTheLibraryNowhereOnJavaLibraryPathFails(@TempDir Path empty) {
        FheException ex = assertThrows(FheException.class,
                () -> NativeLibraryLocator.locate(null, empty.toString()));

        assertTrue(ex.getMessage().contains("blindbean.native.path"), "must name the property to set: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("java.library.path"), ex.getMessage());
    }

    /**
     * Loads {@link FheNativeBridge} in a child JVM whose working directory holds a planted library
     * at every location the old loader searched, so the whole load path is exercised, not just the
     * locator. The child's {@code java.library.path} is an empty directory unless a test says
     * otherwise, so the JVM's own default cannot hide what BlindBean's search does.
     */
    @Nested
    class InAFreshJvm {

        @TempDir Path workDir;
        @TempDir Path emptyDir;

        private List<Path> planted;

        private void plantLibraryInWorkingDirectory() throws IOException {
            planted = new ArrayList<>();
            for (String sub : new String[]{"", "src/main/native", "build-native/Release", "build-native/Debug", "build-native"}) {
                Path dir = Files.createDirectories(workDir.resolve(sub));
                planted.add(Files.writeString(dir.resolve(LIB_FILE), "planted by an attacker"));
            }
        }

        @Test
        void propertyUnsetDoesNotLoadFromWorkingDirectory() throws Exception {
            plantLibraryInWorkingDirectory();

            String outcome = loadBridgeInChild(null);

            assertNoPlantedFileLoaded(outcome);
            assertTrue(outcome.startsWith(FheException.class.getName()), outcome);
            assertTrue(outcome.contains("java.library.path"), outcome);
        }

        @Test
        void propertyPointingAtEmptyDirectoryFailsInsteadOfLoadingFromWorkingDirectory() throws Exception {
            plantLibraryInWorkingDirectory();

            String outcome = loadBridgeInChild(emptyDir.toString());

            assertNoPlantedFileLoaded(outcome);
            assertTrue(outcome.startsWith(FheException.class.getName()), outcome);
            assertTrue(outcome.contains(emptyDir.toString()), "must name the configured directory: " + outcome);
        }

        /** The JDK's default java.library.path on Windows ends in ".", the working directory. */
        @Test
        void relativeJavaLibraryPathEntryDoesNotReachWorkingDirectory() throws Exception {
            plantLibraryInWorkingDirectory();

            String outcome = loadBridgeInChild(null, "." + File.pathSeparator + emptyDir);

            assertNoPlantedFileLoaded(outcome);
            assertTrue(outcome.startsWith(FheException.class.getName()), outcome);
        }

        @Test
        void blankPropertyIsNotResolvedAgainstWorkingDirectory() throws Exception {
            plantLibraryInWorkingDirectory();

            String outcome = loadBridgeInChild("");

            assertNoPlantedFileLoaded(outcome);
            assertTrue(outcome.startsWith(FheException.class.getName()), outcome);
        }

        private void assertNoPlantedFileLoaded(String outcome) {
            assertFalse(outcome.contains(UnsatisfiedLinkError.class.getName()),
                    "the child tried to load a planted file: " + outcome);
            for (Path p : planted) {
                assertFalse(outcome.contains(p.toString()), "the child touched " + p + ": " + outcome);
            }
        }

        private String loadBridgeInChild(String nativePath) throws IOException, InterruptedException {
            return loadBridgeInChild(nativePath, emptyDir.toString());
        }

        private String loadBridgeInChild(String nativePath, String libraryPath) throws IOException, InterruptedException {
            List<String> cmd = new ArrayList<>();
            cmd.add(Path.of(System.getProperty("java.home"), "bin", "java").toString());
            cmd.add("--enable-native-access=ALL-UNNAMED");
            cmd.add("-Djava.library.path=" + libraryPath);
            if (nativePath != null) {
                cmd.add("-D" + NativeLibraryLocator.PROPERTY + "=" + nativePath);
            }
            cmd.add("-cp");
            cmd.add(System.getProperty("java.class.path"));
            cmd.add(LoadBridge.class.getName());

            Process child = new ProcessBuilder(cmd).directory(workDir.toFile()).redirectErrorStream(true).start();
            assertTrue(child.waitFor(60, TimeUnit.SECONDS), "child JVM did not finish");
            String out = new String(child.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            int marker = out.indexOf(LoadBridge.MARKER);
            assertTrue(marker >= 0, "child JVM printed no outcome:\n" + out);
            return out.substring(marker + LoadBridge.MARKER.length()).strip();
        }
    }

    /** Entry point of the child JVM: initialise the bridge and print what happened. */
    public static final class LoadBridge {
        static final String MARKER = "OUTCOME:";

        public static void main(String[] args) {
            Throwable failure = null;
            try {
                Class.forName("se.deversity.blindbean.fhe.FheNativeBridge");
            } catch (ExceptionInInitializerError e) {
                failure = e.getCause();
            } catch (ClassNotFoundException | LinkageError e) {
                failure = e;
            }
            // The whole cause chain: the bridge wraps a failed System.load in an FheException, and
            // the planted file's path then appears only in the cause.
            StringBuilder outcome = new StringBuilder(failure == null ? "loaded" : "");
            for (Throwable t = failure; t != null; t = t.getCause()) {
                outcome.append(t == failure ? "" : " | caused by ").append(t.getClass().getName()).append(": ").append(t.getMessage());
            }
            System.out.println(MARKER + outcome);
        }
    }
}

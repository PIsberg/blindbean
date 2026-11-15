package se.deversity.blindbean.fhe;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

import org.jspecify.annotations.Nullable;

import se.deversity.vibetags.annotations.AISecure;

/**
 * Decides which file {@link FheNativeBridge} loads the {@code blindbean_fhe} library from.
 * <p>
 * Only two places count:
 * <ol>
 *   <li>the directory named by the system property {@code blindbean.native.path}, set by whoever
 *       runs the JVM. When it is set, nothing else is searched: a directory that lacks the library
 *       is an error, not a reason to look elsewhere;</li>
 *   <li>when that property is unset or blank, the <em>absolute</em> entries of
 *       {@code java.library.path}, in order.</li>
 * </ol>
 * The process working directory is never searched. Loading a native library runs its code inside
 * the JVM, so a search path that whoever can write the working directory controls is a way to plant
 * code in every application that uses BFV or CKKS (CWE-427, issue #254). That is also why relative
 * {@code java.library.path} entries are skipped rather than handed to
 * {@link System#loadLibrary(String)}: the JDK's default value on Windows ends in {@code "."}.
 * <p>
 * Kept apart from the bridge so the search order can be tested without loading native code.
 */
@AISecure(aspect = "native-library-search-path")
final class NativeLibraryLocator {

    static final String PROPERTY = "blindbean.native.path";

    private NativeLibraryLocator() {
    }

    /**
     * Returns the absolute path of the library file to pass to {@link System#load(String)}.
     *
     * @param configuredDir the value of {@code blindbean.native.path}, possibly {@code null}
     * @param libraryPath   the value of {@code java.library.path}, possibly {@code null}
     * @throws FheException if no allowed location holds a library for this platform
     */
    static Path locate(@Nullable String configuredDir, @Nullable String libraryPath) {
        Set<String> candidateNames = nativeLibraryFileNames();
        if (configuredDir != null && !configuredDir.isBlank()) {
            // Operator configuration, read from a system property only.
            Path dir = toAbsoluteDir(configuredDir);
            return findIn(dir, candidateNames).orElseThrow(() -> new FheException(
                    "Cannot load blindbean_fhe native library: " + PROPERTY + "=" + configuredDir + " (" + dir
                    + ") contains none of " + candidateNames + ". BlindBean does not fall back to another"
                    + " location when this property is set. Point it at the directory holding the library"
                    + " built for this OS/arch, or unset it to use java.library.path."));
        }
        if (libraryPath != null) {
            for (String entry : libraryPath.split(File.pathSeparator)) {
                Optional<Path> found = absoluteDir(entry).flatMap(dir -> findIn(dir, candidateNames));
                if (found.isPresent()) {
                    return found.get();
                }
            }
        }
        throw new FheException("Cannot load blindbean_fhe native library: " + PROPERTY + " is not set and no"
                + " absolute java.library.path entry holds any of " + candidateNames + " (relative entries"
                + " such as \".\" are skipped). Set -D" + PROPERTY + "=<dir> to the directory holding the"
                + " built library.");
    }

    private static Optional<Path> findIn(Path dir, Set<String> candidateNames) {
        for (String candidateName : candidateNames) {
            Path candidate = dir.resolve(candidateName);
            if (Files.isRegularFile(candidate)) {
                return Optional.of(candidate);
            }
        }
        return Optional.empty();
    }

    private static Path toAbsoluteDir(String configuredDir) {
        try {
            return Path.of(configuredDir).toAbsolutePath();
        } catch (InvalidPathException e) {
            throw new FheException("Cannot load blindbean_fhe native library: " + PROPERTY + "=" + configuredDir
                    + " is not a valid path: " + e.getMessage(), e);
        }
    }

    private static Optional<Path> absoluteDir(String entry) {
        if (entry.isBlank()) {
            return Optional.empty();
        }
        try {
            Path dir = Path.of(entry);
            return dir.isAbsolute() ? Optional.of(dir) : Optional.empty();
        } catch (InvalidPathException e) {
            return Optional.empty();
        }
    }

    private static Set<String> nativeLibraryFileNames() {
        Set<String> candidateNames = new LinkedHashSet<>();
        candidateNames.add(System.mapLibraryName("blindbean_fhe"));

        String osName = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (osName.contains("win")) {
            candidateNames.add("blindbean_fhe.dll");
        } else if (osName.contains("mac")) {
            candidateNames.add("blindbean_fhe.dylib");
            candidateNames.add("libblindbean_fhe.dylib");
        } else {
            candidateNames.add("blindbean_fhe.so");
            candidateNames.add("libblindbean_fhe.so");
        }

        return candidateNames;
    }
}

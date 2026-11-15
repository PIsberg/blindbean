package se.deversity.blindbean.context;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.Set;

import se.deversity.vibetags.annotations.AISecure;

import static java.lang.System.Logger.Level.WARNING;

/**
 * Writes a serialized key bundle to its destination without ever losing the previous one, and
 * without replacing the file that is there.
 *
 * <p>The file is rewritten <em>in place</em>, through any symbolic link, so it keeps its identity:
 * owner, group, mode, ACL, hard links and the link itself stay as the operator set them. #258 wrote
 * a temporary file and renamed it over the destination instead, which kept the old bundle safe but
 * replaced the file: a symlinked key path became a regular file, and a key file shared through its
 * group or ACL became readable by its owner only.
 *
 * <p>Safety comes from a backup instead. Before the existing file is truncated, its bytes are copied
 * to {@code .<name>.bak} beside it, created with the same POSIX mode or ACL so the copy is no more
 * readable than the original. An I/O error during the rewrite puts the old bytes back and removes
 * the backup. If the process dies mid-rewrite, the backup survives and the next export refuses to
 * run until someone restores or removes it, since it may then be the only intact copy.
 */
@AISecure(aspect = "key-file-write")
final class KeyFileWriter {

    private static final System.Logger LOG = System.getLogger(KeyFileWriter.class.getName());

    /** Writes {@code bytes} to an open stream. A seam, so a test can fail part way through. */
    @FunctionalInterface
    interface Sink {
        void write(OutputStream out, byte[] bytes) throws IOException;
    }

    private KeyFileWriter() {
    }

    /** Where the backup of {@code target} lives while it is being rewritten. */
    static Path backupOf(Path target) {
        return target.resolveSibling("." + target.getFileName() + ".bak");
    }

    static void write(Path destination, byte[] bytes) throws IOException {
        write(destination, bytes, OutputStream::write);
    }

    static void write(Path destination, byte[] bytes, Sink sink) throws IOException {
        Path path = destination.toAbsolutePath();
        if (Files.isDirectory(path)) {
            throw new IOException("Destination is a directory: " + path);
        }
        if (!Files.exists(path)) {
            writeNewFile(path, bytes, sink);
            return;
        }

        // The real file behind any symlink: its directory holds the backup, and the link itself is
        // never touched. Opened for writing without truncation first, so a key file we may not write
        // fails here, before a backup exists that would block the next export.
        Path target = path.toRealPath();
        Path backup = backupOf(target);
        if (Files.exists(backup, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("A backup from an interrupted key export exists at " + backup
                + "; it may hold the only intact copy of the previous keys. Restore it over "
                + target + " or remove it, then export again.");
        }
        try (FileChannel channel = FileChannel.open(target, StandardOpenOption.WRITE)) {
            byte[] previous = Files.readAllBytes(target);
            try {
                createBackup(target, backup, previous);
                try {
                    overwrite(channel, bytes, sink);
                } catch (IOException | RuntimeException failure) {
                    restore(channel, previous, backup, failure);
                    throw failure;
                }
            } finally {
                java.util.Arrays.fill(previous, (byte) 0);
            }
        }
        deleteBackup(backup);
    }

    /** No previous bundle: write the file, and remove a partial one if the write fails. */
    private static void writeNewFile(Path path, byte[] bytes, Sink sink) throws IOException {
        try (FileOutputStream out = new FileOutputStream(path.toFile())) {
            sink.write(out, bytes);
            out.flush();
            out.getFD().sync();
        } catch (IOException | RuntimeException failure) {
            // Nothing was there before, so a partial file is only debris. A dangling symlink that
            // led here is the operator's, and stays.
            if (!Files.isSymbolicLink(path)) {
                try {
                    Files.deleteIfExists(path);
                } catch (IOException cleanup) {
                    failure.addSuppressed(cleanup);
                }
            }
            throw failure;
        }
    }

    /** The backup: same bytes, created with the original's mode or ACL, synced before any truncation. */
    private static void createBackup(Path target, Path backup, byte[] previous) throws IOException {
        Files.createFile(backup, sameAccessAs(target));
        try (FileOutputStream out = new FileOutputStream(backup.toFile())) {
            out.write(previous);
            out.flush();
            out.getFD().sync();
        } catch (IOException | RuntimeException failure) {
            try {
                Files.deleteIfExists(backup);
            } catch (IOException cleanup) {
                failure.addSuppressed(cleanup);
            }
            throw failure;
        }
    }

    /**
     * Creation attributes that give a new file the same access as {@code original}. POSIX modes
     * are still narrowed by the umask, which can only make the backup more private, never less.
     */
    private static FileAttribute<?>[] sameAccessAs(Path original) throws IOException {
        Set<String> views = original.getFileSystem().supportedFileAttributeViews();
        if (views.contains("posix")) {
            return new FileAttribute<?>[] {PosixFilePermissions.asFileAttribute(Files.getPosixFilePermissions(original))};
        }
        if (views.contains("acl")) {
            List<AclEntry> acl = Files.getFileAttributeView(original, AclFileAttributeView.class).getAcl();
            return new FileAttribute<?>[] {new FileAttribute<List<AclEntry>>() {
                @Override
                public String name() {
                    return "acl:acl";
                }

                @Override
                public List<AclEntry> value() {
                    return acl;
                }
            }};
        }
        return new FileAttribute<?>[0];
    }

    /** Truncates and rewrites the open file. The stream is not closed: that would close the channel. */
    private static void overwrite(FileChannel channel, byte[] bytes, Sink sink) throws IOException {
        channel.truncate(0);
        channel.position(0);
        OutputStream out = Channels.newOutputStream(channel);
        sink.write(out, bytes);
        out.flush();
        channel.force(true);
    }

    private static void restore(FileChannel channel, byte[] previous, Path backup, Exception failure)
            throws IOException {
        try {
            overwrite(channel, previous, OutputStream::write);
        } catch (IOException | RuntimeException restoreFailure) {
            failure.addSuppressed(restoreFailure);
            throw new IOException("Key export failed and the previous bundle could not be written back; "
                + "it is preserved at " + backup, failure);
        }
        try {
            Files.delete(backup);
        } catch (IOException cleanup) {
            failure.addSuppressed(cleanup);
        }
    }

    /**
     * The new bundle is on disk; the backup is redundant. If it cannot be removed the export still
     * succeeded, but the next one will refuse until it is gone, so say so now.
     */
    private static void deleteBackup(Path backup) {
        try {
            Files.delete(backup);
        } catch (IOException e) {
            LOG.log(WARNING, "Key bundle written, but its backup {0} could not be removed ({1}); the next "
                + "export will refuse until it is deleted", backup, e.toString());
        }
    }
}

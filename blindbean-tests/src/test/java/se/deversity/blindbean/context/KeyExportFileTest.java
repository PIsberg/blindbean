package se.deversity.blindbean.context;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import se.deversity.blindbean.core.Ciphertext;
import se.deversity.blindbean.fhe.FheException;
import se.deversity.blindbean.math.PaillierKeyPair;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.util.EnumSet;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * How {@link BlindContext#exportKeys} treats the file already at the destination.
 *
 * <p>#258 made the export write a temporary file and rename it over the destination, so a failed
 * write could not destroy the previous bundle. The rename also replaced the file itself: a symlinked
 * key path became a regular file, a key file shared through its group or ACL became owner-only, and
 * a hard link kept the old bundle. Those deployments stopped working. The export now rewrites the
 * existing file in place, keeping a backup while it does, so the file keeps its identity and
 * attributes and a failed write still cannot lose the old bundle.
 *
 * <p>Symlink and POSIX-mode tests need a platform that offers them; on Windows without the symlink
 * privilege they do not run, and the Linux and macOS CI legs run them. The hard-link, ACL and
 * failure tests run wherever the filesystem supports them, which includes NTFS.
 */
class KeyExportFileTest {

    @TempDir
    Path dir;

    @AfterEach
    void clear() {
        BlindContext.clear();
    }

    private static void freshKeys() {
        BlindContext.init(new PaillierKeyPair(512));
    }

    /** Exports one bundle, then a second under different keys, and returns the second's ciphertext. */
    private static Ciphertext exportTwice(String path) {
        freshKeys();
        BlindContext.exportKeys(path);
        freshKeys();
        Ciphertext ct = BlindContext.getPaillier().encrypt(BigInteger.valueOf(4242));
        BlindContext.exportKeys(path);
        return ct;
    }

    private static void assertBundleDecrypts(Path bundle, Ciphertext ct) {
        BlindContext.clear();
        BlindContext.loadKeys(bundle.toString());
        assertEquals(BigInteger.valueOf(4242), BlindContext.getPaillier().decrypt(ct),
            "the file must hold the second export's keys");
    }

    @Test
    void aHardLinkToTheKeyFileSeesTheNewBundle() throws Exception {
        Path keys = dir.resolve("keys.bin");
        freshKeys();
        BlindContext.exportKeys(keys.toString());
        Path alias = dir.resolve("alias.bin");
        try {
            Files.createLink(alias, keys);
        } catch (UnsupportedOperationException | IOException e) {
            assumeTrue(false, "hard links unsupported here: " + e);
        }

        freshKeys();
        Ciphertext ct = BlindContext.getPaillier().encrypt(BigInteger.valueOf(4242));
        BlindContext.exportKeys(keys.toString());

        assertArrayEquals(Files.readAllBytes(keys), Files.readAllBytes(alias),
            "the export must rewrite the file itself, not replace it with a new one");
        assertBundleDecrypts(alias, ct);
    }

    @Test
    void exportingThroughASymlinkUpdatesTheTargetAndKeepsTheLink() throws Exception {
        Path real = dir.resolve("real-keys.bin");
        Path link = dir.resolve("keys.bin");
        Files.createFile(real);
        try {
            Files.createSymbolicLink(link, real);
        } catch (UnsupportedOperationException | IOException e) {
            assumeTrue(false, "symbolic links unavailable here: " + e);
        }

        Ciphertext ct = exportTwice(link.toString());

        assertTrue(Files.isSymbolicLink(link), "the key path must still be a symbolic link");
        assertBundleDecrypts(real, ct);
    }

    @Test
    void exportKeepsThePosixModeOfTheExistingFile() throws Exception {
        assumeTrue(dir.getFileSystem().supportedFileAttributeViews().contains("posix"), "no POSIX permissions here");
        Path keys = dir.resolve("keys.bin");
        freshKeys();
        BlindContext.exportKeys(keys.toString());
        // Shared with a service group on purpose: owner read/write, group read.
        Files.setPosixFilePermissions(keys, PosixFilePermissions.fromString("rw-r-----"));

        Ciphertext ct = exportTwice(keys.toString());

        assertEquals("rw-r-----", PosixFilePermissions.toString(Files.getPosixFilePermissions(keys)),
            "an export must not change who can read the key file");
        assertBundleDecrypts(keys, ct);
    }

    @Test
    void exportKeepsTheAclOfTheExistingFile() throws Exception {
        assumeTrue(dir.getFileSystem().supportedFileAttributeViews().contains("acl"), "no ACLs here");
        Path keys = dir.resolve("keys.bin");
        freshKeys();
        BlindContext.exportKeys(keys.toString());

        // An explicit ACL different from what a new file in this directory would inherit.
        AclFileAttributeView view = Files.getFileAttributeView(keys, AclFileAttributeView.class);
        UserPrincipal owner = Files.getOwner(keys);
        AclEntry ownerOnly = AclEntry.newBuilder()
            .setType(AclEntryType.ALLOW)
            .setPrincipal(owner)
            .setPermissions(EnumSet.of(AclEntryPermission.READ_DATA, AclEntryPermission.WRITE_DATA,
                AclEntryPermission.APPEND_DATA, AclEntryPermission.READ_ATTRIBUTES,
                AclEntryPermission.WRITE_ATTRIBUTES, AclEntryPermission.READ_ACL,
                AclEntryPermission.WRITE_ACL, AclEntryPermission.DELETE, AclEntryPermission.SYNCHRONIZE,
                AclEntryPermission.READ_NAMED_ATTRS, AclEntryPermission.WRITE_NAMED_ATTRS))
            .build();
        view.setAcl(List.of(ownerOnly));
        List<AclEntry> before = view.getAcl();

        Ciphertext ct = exportTwice(keys.toString());

        assertEquals(before, Files.getFileAttributeView(keys, AclFileAttributeView.class).getAcl(),
            "an export must not change the key file's ACL");
        assertBundleDecrypts(keys, ct);
    }

    /** A key file that did not exist yet is created readable by its owner only, whatever the umask. */
    @Test
    void aNewKeyFileIsOwnerOnlyOnPosix() throws Exception {
        assumeTrue(dir.getFileSystem().supportedFileAttributeViews().contains("posix"), "no POSIX permissions here");
        Path keys = dir.resolve("keys.bin");
        freshKeys();
        BlindContext.exportKeys(keys.toString());
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(keys)));
    }

    /**
     * The backup holds the previous private keys. Copying the original's mode is not enough: the
     * backup's group is the exporting user's, not the original's, so group bits could open it to
     * people who could not read the original. It must be owner-only while it exists.
     */
    @Test
    void theBackupIsOwnerOnlyWhileTheFileIsRewritten() throws Exception {
        assumeTrue(dir.getFileSystem().supportedFileAttributeViews().contains("posix"), "no POSIX permissions here");
        Path keys = dir.resolve("keys.bin");
        Files.write(keys, new byte[] {7, 7, 7});
        Files.setPosixFilePermissions(keys, PosixFilePermissions.fromString("rw-r-----"));
        String[] seen = new String[1];

        KeyFileWriter.write(keys, new byte[] {1, 2}, (out, bytes) -> {
            seen[0] = PosixFilePermissions.toString(Files.getPosixFilePermissions(KeyFileWriter.backupOf(keys.toRealPath())));
            out.write(bytes);
        });

        assertEquals("rw-------", seen[0], "the backup of the previous keys must be owner-only");
        assertEquals("rw-r-----", PosixFilePermissions.toString(Files.getPosixFilePermissions(keys)),
            "the key file itself keeps its shared mode");
    }

    /**
     * A backup left by an export that was killed mid-write may be the only intact copy of the old
     * keys, so a later export must refuse rather than overwrite it, and touch neither file.
     */
    @Test
    void aBackupLeftByAnInterruptedExportIsNeverOverwritten() throws Exception {
        Path keys = dir.resolve("keys.bin");
        freshKeys();
        BlindContext.exportKeys(keys.toString());
        Path backup = dir.resolve(".keys.bin.bak");
        Files.write(backup, new byte[] {1, 2, 3});
        byte[] keysBefore = Files.readAllBytes(keys);

        freshKeys();
        FheException e = assertThrows(FheException.class, () -> BlindContext.exportKeys(keys.toString()));

        assertTrue(e.getMessage().contains(".keys.bin.bak"), "the refusal must name the backup, got: " + e.getMessage());
        assertArrayEquals(keysBefore, Files.readAllBytes(keys), "the key file must be untouched");
        assertArrayEquals(new byte[] {1, 2, 3}, Files.readAllBytes(backup), "the backup must be untouched");
    }

    /**
     * An I/O error part way through rewriting the file (a full disk, a failing device) must put
     * the previous bundle back, in the same file, and leave no backup behind.
     */
    @Test
    void anIoErrorMidWriteRestoresThePreviousBundleInPlace() throws Exception {
        Path keys = dir.resolve("keys.bin");
        Files.write(keys, new byte[] {9, 9, 9, 9, 9, 9});

        IOException e = assertThrows(IOException.class, () -> KeyFileWriter.write(keys, new byte[] {1, 2, 3, 4},
            (out, bytes) -> {
                out.write(bytes, 0, 2);
                throw new IOException("disk full (simulated)");
            }));

        assertTrue(e.getMessage().contains("disk full"), "the original failure must surface, got: " + e.getMessage());
        assertArrayEquals(new byte[] {9, 9, 9, 9, 9, 9}, Files.readAllBytes(keys),
            "the previous bundle must be restored byte for byte");
        try (var entries = Files.list(dir)) {
            assertEquals(List.of(keys), entries.toList(), "no backup may be left after a successful restore");
        }
    }
}

package se.deversity.blindbean.context;

import se.deversity.blindbean.annotations.Scheme;
import se.deversity.blindbean.math.PaillierKeyPair;
import java.io.Serializable;

import se.deversity.vibetags.annotations.AICallersOnly;
import se.deversity.vibetags.annotations.AILocked;
import se.deversity.vibetags.annotations.AIPrivacy;
import se.deversity.vibetags.annotations.AISchemaSafe;
import se.deversity.vibetags.annotations.AISecureLogging;

/**
 * Encapsulates the entire cryptographic state of BlindContext.
 * Securely holds Paillier KeyPair instances natively and massive
 * native FHE binary arrays encoding Microsoft SEAL engine data.
 */
@AIPrivacy(reason = "Contains serialized Paillier private key material and SEAL key bytes — never log, transmit in plaintext, or expose field values in suggestions or test fixtures")
@AISchemaSafe
@AICallersOnly({"se.deversity.blindbean.context.BlindContext"})
public class KeyBundle implements Serializable {
    @AILocked(reason = "Serialization UID — altering this invalidates all persisted key bundles and breaks key import/export across versions")
    private static final long serialVersionUID = 1L;

    /** Current on-disk format version. Deserialized legacy objects will have formatVersion == 0. */
    private static final short CURRENT_FORMAT_VERSION = 1;

    /** Format version of this bundle. 0 = pre-versioning (legacy), 1 = current. */
    private final short formatVersion;

    @AISecureLogging(AISecureLogging.MaskingPolicy.OMIT)
    private final PaillierKeyPair paillierKeyPair;

    // FHE Parameters
    private final Scheme fheScheme;
    private final int polyModulusDegree;
    private final double scale;
    @AISecureLogging(AISecureLogging.MaskingPolicy.OMIT)
    private final byte[] nativeFhePayload;

    public KeyBundle(PaillierKeyPair paillierKeyPair, Scheme fheScheme, int polyModulusDegree, double scale, byte[] nativeFhePayload) {
        this.formatVersion     = CURRENT_FORMAT_VERSION;
        this.paillierKeyPair   = paillierKeyPair;
        this.fheScheme         = fheScheme;
        this.polyModulusDegree = polyModulusDegree;
        this.scale             = scale;
        this.nativeFhePayload  = nativeFhePayload;
    }

    /**
     * Returns the format version of this bundle.
     * {@code 0} indicates a legacy bundle serialized before versioning was introduced.
     * {@code 1} is the current format.
     */
    public short getFormatVersion() {
        return formatVersion;
    }

    public PaillierKeyPair getPaillierKeyPair() {
        return paillierKeyPair;
    }

    public Scheme getFheScheme() {
        return fheScheme;
    }

    public int getPolyModulusDegree() {
        return polyModulusDegree;
    }

    public double getScale() {
        return scale;
    }

    public byte[] getNativeFhePayload() {
        return nativeFhePayload;
    }
}

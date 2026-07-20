/**
 * The SEAL / Project Panama FFM bridge for BFV and CKKS.
 *
 * <p>Native access ({@code requires java.base}'s FFM) is a runtime capability, granted with
 * {@code --enable-native-access=se.deversity.blindbean.fhe} — it is not declared here. The jar is
 * pure Java and loads the native symbols lazily, so a consumer that never calls {@code bfv()} /
 * {@code ckks()} never touches the native library.
 */
module se.deversity.blindbean.fhe {
    // FheCiphertextNative/FheContext expose Ciphertext (and Scheme) in their public API.
    requires transitive se.deversity.blindbean.core;
    requires static se.deversity.vibetags.annotations;
    requires static org.jspecify;

    exports se.deversity.blindbean.fhe;
}

/**
 * The portable domain model — {@code Ciphertext}, {@code KeyTag}, {@code WrongKeyException}. No
 * cryptography and no native code, so it is cheap for any module to depend on.
 */
module se.deversity.blindbean.core {
    // Ciphertext exposes Scheme in its public API, so consumers of core also need annotations.
    requires transitive se.deversity.blindbean.annotations;
    requires static se.deversity.vibetags.annotations;

    exports se.deversity.blindbean.core;
}

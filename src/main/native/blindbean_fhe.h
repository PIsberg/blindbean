#ifndef BLINDBEAN_FHE_H
#define BLINDBEAN_FHE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/**
 * A stubbed C API for FHE (Fully Homomorphic Encryption) operations.
 * This is designed to be wrapped by Project Panama (jextract).
 * In a real-world scenario, this would wrap Microsoft SEAL or OpenFHE C++ APIs.
 */

// Opaque handles
typedef void* FheContext;
typedef void* FheCiphertext;
typedef void* FhePlaintext;

#ifdef __cplusplus
extern "C" {
#endif

/** Initializes the BFV context and returns a handle. */
FheContext fhe_init_bfv(uint32_t poly_modulus_degree);

/** Destroys the context and frees memory. */
void fhe_destroy_context(FheContext ctx);

/** Encrypts a 64-bit integer into a Ciphertext handle. */
FheCiphertext fhe_encrypt_long(FheContext ctx, int64_t value);

/** Decrypts a Ciphertext handle back to a 64-bit integer. */
int64_t fhe_decrypt_long(FheContext ctx, FheCiphertext ct);

/** Homomorphically adds two ciphertexts, returning a new ciphertext. */
FheCiphertext fhe_add(FheContext ctx, FheCiphertext a, FheCiphertext b);

/** Homomorphically multiplies two ciphertexts, returning a new ciphertext. */
FheCiphertext fhe_multiply(FheContext ctx, FheCiphertext a, FheCiphertext b);

/** Computes the remaining noise budget in bits. Warns user if it's too low. */
int32_t fhe_noise_budget(FheContext ctx, FheCiphertext ct);

/** Frees a ciphertext handle. */
void fhe_free_ciphertext(FheCiphertext ct);

#ifdef __cplusplus
}
#endif

#endif // BLINDBEAN_FHE_H

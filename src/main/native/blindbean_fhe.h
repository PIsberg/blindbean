#ifndef BLINDBEAN_FHE_H
#define BLINDBEAN_FHE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/**
 * Production C API for FHE (Fully Homomorphic Encryption) operations.
 * Backed by Microsoft SEAL 4.1 — supports BFV (exact integer) and CKKS (approximate real).
 * Designed as extern "C" so Java 26 Project Panama FFM can downcall via MethodHandle.
 */

// Opaque handles — point to internal C++ objects
typedef void* FheContext;
typedef void* FheCiphertext;
typedef void* FhePlaintext;

#ifdef _WIN32
  #ifdef BLINDBEAN_EXPORTS
    #define BLINDBEAN_API __declspec(dllexport)
  #else
    #define BLINDBEAN_API __declspec(dllimport)
  #endif
#else
  #define BLINDBEAN_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================
// Context Lifecycle
// ============================================================

/** Initializes a BFV context with the given polynomial modulus degree.
 *  Uses SEAL recommended 128-bit security parameters.
 *  Returns NULL on failure. */
BLINDBEAN_API FheContext fhe_init_bfv(uint32_t poly_modulus_degree);

/** Initializes a CKKS context with the given polynomial modulus degree and scale.
 *  Returns NULL on failure. */
BLINDBEAN_API FheContext fhe_init_ckks(uint32_t poly_modulus_degree, double scale);

/** Destroys the context and frees all associated memory. */
BLINDBEAN_API void fhe_destroy_context(FheContext ctx);

// ============================================================
// BFV — Exact Integer Encryption
// ============================================================

/** Encrypts a 64-bit integer using BFV. Returns NULL on failure. */
BLINDBEAN_API FheCiphertext fhe_encrypt_long(FheContext ctx, int64_t value);

/** Decrypts a BFV ciphertext back to a 64-bit integer. Returns 0 on failure. */
BLINDBEAN_API int64_t fhe_decrypt_long(FheContext ctx, FheCiphertext ct);

/** Encrypts an array of 64-bit integers using BFV Batching. Returns NULL on failure. */
BLINDBEAN_API FheCiphertext fhe_encrypt_long_array(FheContext ctx, const int64_t* values, size_t count);

/** Decrypts a BFV ciphertext back into a 64-bit array buffer. Returns elements decoded or 0 on failure. */
BLINDBEAN_API int32_t fhe_decrypt_long_array(FheContext ctx, FheCiphertext ct, int64_t* out_values, size_t max_count);

// ============================================================
// CKKS — Approximate Real Encryption
// ============================================================

/** Encrypts a double using CKKS. Returns NULL on failure. */
BLINDBEAN_API FheCiphertext fhe_encrypt_double(FheContext ctx, double value);

/** Decrypts a CKKS ciphertext back to a double. Returns 0.0 on failure. */
BLINDBEAN_API double fhe_decrypt_double(FheContext ctx, FheCiphertext ct);

// ============================================================
// Homomorphic Operations
// ============================================================

/** Homomorphically adds two ciphertexts, returning a new ciphertext.
 *  Both ciphertexts must belong to the same context. */
BLINDBEAN_API FheCiphertext fhe_add(FheContext ctx, FheCiphertext a, FheCiphertext b);

/** Homomorphically subtracts two ciphertexts, returning a new ciphertext.
 *  Both ciphertexts must belong to the same context. */
BLINDBEAN_API FheCiphertext fhe_subtract(FheContext ctx, FheCiphertext a, FheCiphertext b);

/** Homomorphically multiplies two ciphertexts, returning a new ciphertext.
 *  Automatically relinearizes after multiplication. */
BLINDBEAN_API FheCiphertext fhe_multiply(FheContext ctx, FheCiphertext a, FheCiphertext b);

/** Relinearizes a ciphertext in-place (reduces size after multiplication). */
BLINDBEAN_API void fhe_relinearize(FheContext ctx, FheCiphertext ct);

/** CKKS: rescales a ciphertext in-place (reduces scale after multiplication). */
BLINDBEAN_API void fhe_rescale(FheContext ctx, FheCiphertext ct);

// ============================================================
// Diagnostics
// ============================================================

/** Computes the remaining noise budget (in bits) for a BFV ciphertext.
 *  Returns 0 if the ciphertext is too noisy to decrypt correctly.
 *  For CKKS, always returns -1 (noise budget is not a meaningful concept). */
BLINDBEAN_API int32_t fhe_noise_budget(FheContext ctx, FheCiphertext ct);

// ============================================================
// Serialization
// ============================================================

/** Serializes a ciphertext into the caller-supplied buffer.
 *  On entry, *out_len must contain the buffer capacity.
 *  On exit, *out_len contains the actual bytes written.
 *  Returns 0 on success, -1 if the buffer is too small. */
BLINDBEAN_API int32_t fhe_serialize_ciphertext(FheContext ctx, FheCiphertext ct,
                                  uint8_t* out_buf, size_t* out_len);

/** Deserializes a ciphertext from a byte buffer. Returns NULL on failure. */
BLINDBEAN_API FheCiphertext fhe_deserialize_ciphertext(FheContext ctx,
                                          const uint8_t* buf, size_t len);

// ============================================================
// Memory Management
// ============================================================

/** Frees a ciphertext handle. */
BLINDBEAN_API void fhe_free_ciphertext(FheCiphertext ct);

#ifdef __cplusplus
}
#endif

#endif // BLINDBEAN_FHE_H

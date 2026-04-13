#include "blindbean_fhe.h"
#include <stdlib.h>
#include <stdio.h>

// A dummy implementation for the FHE backend to prove Project Panama bridge integration

FheContext fhe_init_bfv(uint32_t poly_modulus_degree) {
    printf("[NATIVE] Initializing BFV Context (Dummy) with poly_modulus_degree=%d\n", poly_modulus_degree);
    void* ctx = malloc(sizeof(int)); 
    return (FheContext)ctx;
}

void fhe_destroy_context(FheContext ctx) {
    if (ctx) {
        printf("[NATIVE] Destroying Context\n");
        free(ctx);
    }
}

FheCiphertext fhe_encrypt_long(FheContext ctx, int64_t value) {
    // Dummy: just returning the pointer casted directly to simulate an encrypted container in memory.
    // In a real scenario, this allocates a SEAL::Ciphertext.
    int64_t* ptr = (int64_t*)malloc(sizeof(int64_t));
    *ptr = value; // storing in plaintext just for dummy execution
    return (FheCiphertext)ptr;
}

int64_t fhe_decrypt_long(FheContext ctx, FheCiphertext ct) {
    if (ct) {
        int64_t* ptr = (int64_t*)ct;
        return *ptr;
    }
    return 0;
}

FheCiphertext fhe_add(FheContext ctx, FheCiphertext a, FheCiphertext b) {
    int64_t* pA = (int64_t*)a;
    int64_t* pB = (int64_t*)b;
    int64_t* res = (int64_t*)malloc(sizeof(int64_t));
    if (pA && pB && res) {
        *res = (*pA) + (*pB);
        printf("[NATIVE] Homomorphic Add (Dummy): %lld + %lld = %lld\n", *pA, *pB, *res);
    }
    return (FheCiphertext)res;
}

FheCiphertext fhe_multiply(FheContext ctx, FheCiphertext a, FheCiphertext b) {
    int64_t* pA = (int64_t*)a;
    int64_t* pB = (int64_t*)b;
    int64_t* res = (int64_t*)malloc(sizeof(int64_t));
    if (pA && pB && res) {
        *res = (*pA) * (*pB);
    }
    return (FheCiphertext)res;
}

int32_t fhe_noise_budget(FheContext ctx, FheCiphertext ct) {
    // Dummy noise budget returning arbitrary high amount.
    return 80;
}

void fhe_free_ciphertext(FheCiphertext ct) {
    if (ct) {
        free(ct);
    }
}

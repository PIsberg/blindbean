#include "blindbean_fhe.h"

#include <seal/seal.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <vector>

// ============================================================
// Internal context structure — hidden behind the opaque handle
// ============================================================

struct BlindBeanContext {
    std::shared_ptr<seal::SEALContext> sealCtx;
    std::unique_ptr<seal::Encryptor>   encryptor;
    std::unique_ptr<seal::Decryptor>   decryptor;
    std::unique_ptr<seal::Evaluator>   evaluator;
    std::unique_ptr<seal::KeyGenerator> keygen;
    seal::PublicKey   publicKey;
    seal::SecretKey   secretKey;
    seal::RelinKeys   relinKeys;
    double            scale;     // CKKS scale; 0 for BFV
    bool              isCkks;
};

// ============================================================
// Context Lifecycle
// ============================================================

extern "C" FheContext fhe_init_bfv(uint32_t poly_modulus_degree) {
    try {
        seal::EncryptionParameters parms(seal::scheme_type::bfv);
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(poly_modulus_degree));
        parms.set_plain_modulus(seal::PlainModulus::Batching(poly_modulus_degree, 20));

        auto sealCtx = std::make_shared<seal::SEALContext>(parms);
        if (!sealCtx->parameters_set()) {
            fprintf(stderr, "[SEAL] BFV parameter validation failed\n");
            return nullptr;
        }

        auto* ctx = new BlindBeanContext();
        ctx->sealCtx = sealCtx;
        ctx->isCkks  = false;
        ctx->scale   = 0.0;

        ctx->keygen = std::make_unique<seal::KeyGenerator>(*sealCtx);
        ctx->secretKey = ctx->keygen->secret_key();
        ctx->keygen->create_public_key(ctx->publicKey);
        ctx->keygen->create_relin_keys(ctx->relinKeys);

        ctx->encryptor = std::make_unique<seal::Encryptor>(*sealCtx, ctx->publicKey);
        ctx->decryptor = std::make_unique<seal::Decryptor>(*sealCtx, ctx->secretKey);
        ctx->evaluator = std::make_unique<seal::Evaluator>(*sealCtx);

        return static_cast<FheContext>(ctx);
    } catch (const std::exception& e) {
        fprintf(stderr, "[SEAL] fhe_init_bfv error: %s\n", e.what());
        return nullptr;
    }
}

extern "C" FheContext fhe_init_ckks(uint32_t poly_modulus_degree, double scale) {
    try {
        seal::EncryptionParameters parms(seal::scheme_type::ckks);
        parms.set_poly_modulus_degree(poly_modulus_degree);
        // Use recommended coeff_modulus for 128-bit security at this degree
        parms.set_coeff_modulus(seal::CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));

        auto sealCtx = std::make_shared<seal::SEALContext>(parms);
        if (!sealCtx->parameters_set()) {
            fprintf(stderr, "[SEAL] CKKS parameter validation failed\n");
            return nullptr;
        }

        auto* ctx = new BlindBeanContext();
        ctx->sealCtx = sealCtx;
        ctx->isCkks  = true;
        ctx->scale   = scale;

        ctx->keygen = std::make_unique<seal::KeyGenerator>(*sealCtx);
        ctx->secretKey = ctx->keygen->secret_key();
        ctx->keygen->create_public_key(ctx->publicKey);
        ctx->keygen->create_relin_keys(ctx->relinKeys);

        ctx->encryptor = std::make_unique<seal::Encryptor>(*sealCtx, ctx->publicKey);
        ctx->decryptor = std::make_unique<seal::Decryptor>(*sealCtx, ctx->secretKey);
        ctx->evaluator = std::make_unique<seal::Evaluator>(*sealCtx);

        return static_cast<FheContext>(ctx);
    } catch (const std::exception& e) {
        fprintf(stderr, "[SEAL] fhe_init_ckks error: %s\n", e.what());
        return nullptr;
    }
}

extern "C" void fhe_destroy_context(FheContext handle) {
    if (handle) {
        auto* ctx = static_cast<BlindBeanContext*>(handle);
        delete ctx;
    }
}

// ============================================================
// BFV — Exact Integer Encryption
// ============================================================

extern "C" FheCiphertext fhe_encrypt_long(FheContext handle, int64_t value) {
    try {
        auto* ctx = static_cast<BlindBeanContext*>(handle);
        if (!ctx || ctx->isCkks) return nullptr;

        // Encode the single int64 into a plaintext using BatchEncoder
        seal::BatchEncoder encoder(*ctx->sealCtx);
        size_t slot_count = encoder.slot_count();
        std::vector<int64_t> pod(slot_count, 0);
        pod[0] = value;

        seal::Plaintext plain;
        encoder.encode(pod, plain);

        auto* ct = new seal::Ciphertext();
        ctx->encryptor->encrypt(plain, *ct);
        return static_cast<FheCiphertext>(ct);
    } catch (const std::exception& e) {
        fprintf(stderr, "[SEAL] fhe_encrypt_long error: %s\n", e.what());
        return nullptr;
    }
}

extern "C" int64_t fhe_decrypt_long(FheContext handle, FheCiphertext ctHandle) {
    try {
        auto* ctx = static_cast<BlindBeanContext*>(handle);
        auto* ct  = static_cast<seal::Ciphertext*>(ctHandle);
        if (!ctx || !ct || ctx->isCkks) return 0;

        seal::Plaintext plain;
        ctx->decryptor->decrypt(*ct, plain);

        seal::BatchEncoder encoder(*ctx->sealCtx);
        std::vector<int64_t> result;
        encoder.decode(plain, result);
        return result[0];
    } catch (const std::exception& e) {
        fprintf(stderr, "[SEAL] fhe_decrypt_long error: %s\n", e.what());
        return 0;
    }
}

// ============================================================
// CKKS — Approximate Real Encryption
// ============================================================

extern "C" FheCiphertext fhe_encrypt_double(FheContext handle, double value) {
    try {
        auto* ctx = static_cast<BlindBeanContext*>(handle);
        if (!ctx || !ctx->isCkks) return nullptr;

        seal::CKKSEncoder encoder(*ctx->sealCtx);
        seal::Plaintext plain;
        encoder.encode(value, ctx->scale, plain);

        auto* ct = new seal::Ciphertext();
        ctx->encryptor->encrypt(plain, *ct);
        return static_cast<FheCiphertext>(ct);
    } catch (const std::exception& e) {
        fprintf(stderr, "[SEAL] fhe_encrypt_double error: %s\n", e.what());
        return nullptr;
    }
}

extern "C" double fhe_decrypt_double(FheContext handle, FheCiphertext ctHandle) {
    try {
        auto* ctx = static_cast<BlindBeanContext*>(handle);
        auto* ct  = static_cast<seal::Ciphertext*>(ctHandle);
        if (!ctx || !ct || !ctx->isCkks) return 0.0;

        seal::Plaintext plain;
        ctx->decryptor->decrypt(*ct, plain);

        seal::CKKSEncoder encoder(*ctx->sealCtx);
        std::vector<double> result;
        encoder.decode(plain, result);
        return result[0];
    } catch (const std::exception& e) {
        fprintf(stderr, "[SEAL] fhe_decrypt_double error: %s\n", e.what());
        return 0.0;
    }
}

// ============================================================
// Homomorphic Operations
// ============================================================

extern "C" FheCiphertext fhe_add(FheContext handle, FheCiphertext aHandle, FheCiphertext bHandle) {
    try {
        auto* ctx = static_cast<BlindBeanContext*>(handle);
        auto* a   = static_cast<seal::Ciphertext*>(aHandle);
        auto* b   = static_cast<seal::Ciphertext*>(bHandle);
        if (!ctx || !a || !b) return nullptr;

        auto* result = new seal::Ciphertext();
        ctx->evaluator->add(*a, *b, *result);
        return static_cast<FheCiphertext>(result);
    } catch (const std::exception& e) {
        fprintf(stderr, "[SEAL] fhe_add error: %s\n", e.what());
        return nullptr;
    }
}

extern "C" FheCiphertext fhe_subtract(FheContext handle, FheCiphertext aHandle, FheCiphertext bHandle) {
    try {
        auto* ctx = static_cast<BlindBeanContext*>(handle);
        auto* a   = static_cast<seal::Ciphertext*>(aHandle);
        auto* b   = static_cast<seal::Ciphertext*>(bHandle);
        if (!ctx || !a || !b) return nullptr;

        auto* result = new seal::Ciphertext();
        ctx->evaluator->sub(*a, *b, *result);
        return static_cast<FheCiphertext>(result);
    } catch (const std::exception& e) {
        fprintf(stderr, "[SEAL] fhe_subtract error: %s\n", e.what());
        return nullptr;
    }
}

extern "C" FheCiphertext fhe_multiply(FheContext handle, FheCiphertext aHandle, FheCiphertext bHandle) {
    try {
        auto* ctx = static_cast<BlindBeanContext*>(handle);
        auto* a   = static_cast<seal::Ciphertext*>(aHandle);
        auto* b   = static_cast<seal::Ciphertext*>(bHandle);
        if (!ctx || !a || !b) return nullptr;

        auto* result = new seal::Ciphertext();
        ctx->evaluator->multiply(*a, *b, *result);
        // Auto-relinearize to keep ciphertext size manageable
        ctx->evaluator->relinearize_inplace(*result, ctx->relinKeys);
        return static_cast<FheCiphertext>(result);
    } catch (const std::exception& e) {
        fprintf(stderr, "[SEAL] fhe_multiply error: %s\n", e.what());
        return nullptr;
    }
}

extern "C" void fhe_relinearize(FheContext handle, FheCiphertext ctHandle) {
    try {
        auto* ctx = static_cast<BlindBeanContext*>(handle);
        auto* ct  = static_cast<seal::Ciphertext*>(ctHandle);
        if (!ctx || !ct) return;
        ctx->evaluator->relinearize_inplace(*ct, ctx->relinKeys);
    } catch (const std::exception& e) {
        fprintf(stderr, "[SEAL] fhe_relinearize error: %s\n", e.what());
    }
}

extern "C" void fhe_rescale(FheContext handle, FheCiphertext ctHandle) {
    try {
        auto* ctx = static_cast<BlindBeanContext*>(handle);
        auto* ct  = static_cast<seal::Ciphertext*>(ctHandle);
        if (!ctx || !ct || !ctx->isCkks) return;
        ctx->evaluator->rescale_to_next_inplace(*ct);
    } catch (const std::exception& e) {
        fprintf(stderr, "[SEAL] fhe_rescale error: %s\n", e.what());
    }
}

// ============================================================
// Diagnostics
// ============================================================

extern "C" int32_t fhe_noise_budget(FheContext handle, FheCiphertext ctHandle) {
    try {
        auto* ctx = static_cast<BlindBeanContext*>(handle);
        auto* ct  = static_cast<seal::Ciphertext*>(ctHandle);
        if (!ctx || !ct) return 0;

        // Noise budget is meaningful for BFV/BGV, not for CKKS
        if (ctx->isCkks) return -1;

        return static_cast<int32_t>(ctx->decryptor->invariant_noise_budget(*ct));
    } catch (const std::exception& e) {
        fprintf(stderr, "[SEAL] fhe_noise_budget error: %s\n", e.what());
        return 0;
    }
}

// ============================================================
// Serialization
// ============================================================

extern "C" int32_t fhe_serialize_ciphertext(FheContext handle, FheCiphertext ctHandle,
                                             uint8_t* out_buf, size_t* out_len) {
    try {
        auto* ctx = static_cast<BlindBeanContext*>(handle);
        auto* ct  = static_cast<seal::Ciphertext*>(ctHandle);
        if (!ctx || !ct || !out_len) return -1;

        // Serialize to a stringstream first to measure size
        std::ostringstream oss(std::ios::binary);
        ct->save(oss);
        std::string data = oss.str();

        if (!out_buf || *out_len < data.size()) {
            *out_len = data.size();
            return -1; // buffer too small — caller can retry with correct size
        }

        std::memcpy(out_buf, data.data(), data.size());
        *out_len = data.size();
        return 0;
    } catch (const std::exception& e) {
        fprintf(stderr, "[SEAL] fhe_serialize_ciphertext error: %s\n", e.what());
        return -1;
    }
}

extern "C" FheCiphertext fhe_deserialize_ciphertext(FheContext handle,
                                                      const uint8_t* buf, size_t len) {
    try {
        auto* ctx = static_cast<BlindBeanContext*>(handle);
        if (!ctx || !buf || len == 0) return nullptr;

        std::string data(reinterpret_cast<const char*>(buf), len);
        std::istringstream iss(data, std::ios::binary);

        auto* ct = new seal::Ciphertext();
        ct->load(*ctx->sealCtx, iss);
        return static_cast<FheCiphertext>(ct);
    } catch (const std::exception& e) {
        fprintf(stderr, "[SEAL] fhe_deserialize_ciphertext error: %s\n", e.what());
        return nullptr;
    }
}

// ============================================================
// Memory Management
// ============================================================

extern "C" void fhe_free_ciphertext(FheCiphertext ctHandle) {
    if (ctHandle) {
        auto* ct = static_cast<seal::Ciphertext*>(ctHandle);
        delete ct;
    }
}

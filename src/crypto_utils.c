#include "crypto_utils.h"
#include <string.h>

int crypto_init(crypto_context_t *ctx, const char* password) {  // Added password parameter
    if (!ctx || !password) return -1;
    
    printf("DEBUG: crypto_init starting\n");
    memset(ctx, 0, sizeof(crypto_context_t));
    
    // Initialize mbedTLS contexts
    mbedtls_aes_init(&ctx->aes_ctx);
    mbedtls_md_init(&ctx->hmac_ctx);
    mbedtls_entropy_init(&ctx->entropy);
    mbedtls_ctr_drbg_init(&ctx->ctr_drbg);
    
    // Seed random number generator
    const char* pers = "drone_crypto";
    int ret = mbedtls_ctr_drbg_seed(&ctx->ctr_drbg, mbedtls_entropy_func, 
                                    &ctx->entropy, (const unsigned char*)pers, strlen(pers));
    if (ret != 0) {
        printf("DEBUG: CTR_DRBG seed failed: %d\n", ret);
        return ret;
    }
    
    // Derive keys from password using your existing derive_keys function
   /* uint8_t salt[16] = "drone_salt_12345";
    ret = derive_keys(ctx, password, salt);
    if (ret != 0) {
        printf("DEBUG: Key derivation failed: %d\n", ret);
        return ret;
    }*/
    
    // Set AES encryption key
    ret = mbedtls_aes_setkey_enc(&ctx->aes_ctx, ctx->aes_key, AES_KEY_SIZE * 8);
    if (ret != 0) {
        printf("DEBUG: AES key setup failed: %d\n", ret);
        return ret;
    }

    // Setup HMAC context
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    ret = mbedtls_md_setup(&ctx->hmac_ctx, md_info, 1);
    if (ret != 0) {
        printf("DEBUG: HMAC setup failed: %d\n", ret);
        return ret;
    }
    
    ret = mbedtls_md_hmac_starts(&ctx->hmac_ctx, ctx->hmac_key, AES_KEY_SIZE);
    if (ret != 0) {
        printf("DEBUG: HMAC start failed: %d\n", ret);
        return ret;
    }
    
    ctx->sequence_number = 0;
    printf("DEBUG: crypto_init completed successfully\n");
    return 0;
}

void crypto_cleanup(crypto_context_t *ctx) {
    if (!ctx) return;
    
    mbedtls_aes_free(&ctx->aes_ctx);
    mbedtls_md_free(&ctx->hmac_ctx);
    mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
    mbedtls_entropy_free(&ctx->entropy);
    
    memset(ctx, 0, sizeof(crypto_context_t));
}

// Add the missing encrypt_message function that sender.c needs
int encrypt_message(crypto_context_t* ctx, const uint8_t* plaintext, 
                   size_t plaintext_len, secure_message_t* secure_msg, 
                   uint8_t msg_type) {
    printf("DEBUG: encrypt_message called\n");
    
    if (!ctx || !plaintext || !secure_msg) {
        return -1;
    }
    
    // Initialize message header
    secure_msg->message_id = rand();
    secure_msg->timestamp = get_timestamp();
    secure_msg->sequence_number = ++ctx->sequence_number;
    secure_msg->message_type = msg_type;
    secure_msg->data_length = (uint16_t)plaintext_len;
    secure_msg->reserved = 0;
    
    // Generate random IV
    int ret = mbedtls_ctr_drbg_random(&ctx->ctr_drbg, secure_msg->iv, AES_IV_SIZE);
    if (ret != 0) {
        printf("DEBUG: IV generation failed: %d\n", ret);
        return ret;
    }
    
    // For testing, just copy plaintext (implement real AES-CBC later)
    memcpy(secure_msg->encrypted_data, plaintext, plaintext_len);
    
    // Calculate HMAC
    mbedtls_md_hmac_reset(&ctx->hmac_ctx);
    mbedtls_md_hmac_update(&ctx->hmac_ctx, (uint8_t*)secure_msg, 
                           sizeof(secure_message_t) - HMAC_SIZE);
    mbedtls_md_hmac_finish(&ctx->hmac_ctx, secure_msg->hmac);
    
    printf("DEBUG: encrypt_message completed successfully\n");
    return 0;
}

// Keep your existing functions but they won't be used by sender.c
int crypto_encrypt(crypto_context_t *ctx, const uint8_t *plaintext, 
                  size_t plaintext_len, uint8_t *ciphertext, size_t *ciphertext_len) {
    if (!ctx) return -1;
    memcpy(ciphertext, plaintext, plaintext_len);
    *ciphertext_len = plaintext_len;
    return 0;
}

int crypto_decrypt(crypto_context_t *ctx, const uint8_t *ciphertext,
                  size_t ciphertext_len, uint8_t *plaintext, size_t *plaintext_len) {
    if (!ctx) return -1;
    memcpy(plaintext, ciphertext, ciphertext_len);
    *plaintext_len = ciphertext_len;
    return 0;
}
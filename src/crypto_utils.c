#include "crypto_utils.h"
#include <string.h>

int crypto_init(crypto_context_t *ctx, const char* password) {
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
    uint8_t salt[16] = "drone_salt_12345";
    ret = derive_keys(ctx, password, salt);
    if (ret != 0) {
        printf("DEBUG: Key derivation failed: %d\n", ret);
        return ret;
    }
    
    // Set AES encryption key (we'll set decryption key when needed)
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

// PKCS#7 padding function
static void add_pkcs7_padding(uint8_t* data, size_t data_len, size_t block_size) {
    size_t padding = block_size - (data_len % block_size);
    if (padding == 0) padding = block_size;
    
    printf("DEBUG: Adding PKCS#7 padding - data_len=%zu, padding=%zu\n", data_len, padding);
    
    for (size_t i = 0; i < padding; i++) {
        data[data_len + i] = (uint8_t)padding;
    }
    
    printf("DEBUG: After padding - total_len=%zu, last 16 bytes: ", data_len + padding);
    for (size_t i = (data_len + padding > 16) ? data_len + padding - 16 : 0; i < data_len + padding; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

// Remove PKCS#7 padding function
static int remove_pkcs7_padding(const uint8_t* data, size_t data_len, size_t* actual_len) {
    if (data_len == 0) return -1;
    
    uint8_t padding = data[data_len - 1];
    
    printf("DEBUG: Padding removal - data_len=%zu, padding_byte=%u\n", data_len, padding);
    printf("DEBUG: Last 16 bytes: ");
    for (int i = (int)data_len - 16; i < (int)data_len; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
    
    if (padding > 16 || padding == 0) {
        printf("DEBUG: Invalid padding value: %u\n", padding);
        return -1;
    }
    
    // Verify padding bytes
    for (size_t i = data_len - padding; i < data_len; i++) {
        if (data[i] != padding) {
            printf("DEBUG: Padding verification failed at index %zu: expected %u, got %u\n", 
                   i, padding, data[i]);
            return -1;
        }
    }
    
    *actual_len = data_len - padding;
    printf("DEBUG: Padding removal successful - actual_len=%zu\n", *actual_len);
    return 0;
}

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
    
    // Prepare data for encryption with PKCS#7 padding
    uint8_t padded_data[MAX_DATA_SIZE];
    memcpy(padded_data, plaintext, plaintext_len);
    add_pkcs7_padding(padded_data, plaintext_len, 16);
    size_t padded_len = ((plaintext_len + 15) / 16) * 16;
    
    printf("DEBUG: Encrypting %zu bytes (padded to %zu)\n", plaintext_len, padded_len);
    
    // Encrypt with AES-CBC
    mbedtls_aes_context aes_ctx;
    mbedtls_aes_init(&aes_ctx);
    
    ret = mbedtls_aes_setkey_enc(&aes_ctx, ctx->aes_key, AES_KEY_SIZE * 8);
    if (ret != 0) {
        printf("DEBUG: AES encrypt key setup failed: %d\n", ret);
        mbedtls_aes_free(&aes_ctx);
        return ret;
    }
    
    uint8_t iv_copy[AES_IV_SIZE];
    memcpy(iv_copy, secure_msg->iv, AES_IV_SIZE);
    
    ret = mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT, padded_len,
                                iv_copy, padded_data, secure_msg->encrypted_data);
    
    mbedtls_aes_free(&aes_ctx);
    
    if (ret != 0) {
        printf("DEBUG: AES encryption failed: %d\n", ret);
        return ret;
    }
    
    // Calculate HMAC using the same field-by-field method
    uint8_t hmac_input[1024];
    size_t offset = 0;

    memcpy(hmac_input + offset, &secure_msg->message_id, sizeof(uint32_t)); offset += sizeof(uint32_t);
    memcpy(hmac_input + offset, &secure_msg->timestamp, sizeof(uint32_t)); offset += sizeof(uint32_t);
    memcpy(hmac_input + offset, &secure_msg->sequence_number, sizeof(uint32_t)); offset += sizeof(uint32_t);
    memcpy(hmac_input + offset, &secure_msg->data_length, sizeof(uint16_t)); offset += sizeof(uint16_t);
    memcpy(hmac_input + offset, &secure_msg->message_type, sizeof(uint8_t)); offset += sizeof(uint8_t);
    memcpy(hmac_input + offset, &secure_msg->reserved, sizeof(uint8_t)); offset += sizeof(uint8_t);
    memcpy(hmac_input + offset, secure_msg->iv, AES_IV_SIZE); offset += AES_IV_SIZE;
    memcpy(hmac_input + offset, secure_msg->encrypted_data, padded_len); offset += padded_len;

    ret = mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                          ctx->hmac_key, HMAC_KEY_SIZE,
                          hmac_input, offset, secure_msg->hmac);
    if (ret != 0) {
        printf("DEBUG: HMAC generation failed: %d\n", ret);
        return ret;
    }
    
    printf("DEBUG: encrypt_message completed successfully\n");
    return 0;
}

int decrypt_message(crypto_context_t* ctx, const secure_message_t* secure_msg, 
                   uint8_t* decrypted_data, size_t* decrypted_len) {
    if (!ctx || !secure_msg || !decrypted_data || !decrypted_len) {
        printf("DEBUG: decrypt_message - null pointer check failed\n");
        return -1;
    }

    printf("DEBUG: decrypt_message - msg_id=%u, type=%u, data_len=%u\n", 
           secure_msg->message_id, secure_msg->message_type, secure_msg->data_length);

    // Verify HMAC first
    uint8_t hmac_input[1024];
    size_t offset = 0;
    size_t padded_len = ((secure_msg->data_length + 15) / 16) * 16;
    
    printf("DEBUG: decrypt_message - padded_len=%zu\n", padded_len);
    
    memcpy(hmac_input + offset, &secure_msg->message_id, sizeof(uint32_t)); offset += sizeof(uint32_t);
    memcpy(hmac_input + offset, &secure_msg->timestamp, sizeof(uint32_t)); offset += sizeof(uint32_t);
    memcpy(hmac_input + offset, &secure_msg->sequence_number, sizeof(uint32_t)); offset += sizeof(uint32_t);
    memcpy(hmac_input + offset, &secure_msg->data_length, sizeof(uint16_t)); offset += sizeof(uint16_t);
    memcpy(hmac_input + offset, &secure_msg->message_type, sizeof(uint8_t)); offset += sizeof(uint8_t);
    memcpy(hmac_input + offset, &secure_msg->reserved, sizeof(uint8_t)); offset += sizeof(uint8_t);
    memcpy(hmac_input + offset, secure_msg->iv, AES_IV_SIZE); offset += AES_IV_SIZE;
    memcpy(hmac_input + offset, secure_msg->encrypted_data, padded_len); offset += padded_len;
    
    uint8_t computed_hmac[HMAC_SIZE];
    int ret = mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                              ctx->hmac_key, HMAC_KEY_SIZE,
                              hmac_input, offset, computed_hmac);
    
    printf("DEBUG: HMAC calc result: %d\n", ret);
    if (ret != 0) return -2;
    
    printf("DEBUG: Received HMAC: ");
    for(int i = 0; i < 8; i++) printf("%02x ", secure_msg->hmac[i]);
    printf("\nDEBUG: Computed HMAC: ");
    for(int i = 0; i < 8; i++) printf("%02x ", computed_hmac[i]);
    printf("\n");
    
    if (memcmp(computed_hmac, secure_msg->hmac, HMAC_SIZE) != 0) {
        printf("DEBUG: HMAC verification failed\n");
        return -3; // HMAC verification failed
    }
    
    printf("DEBUG: HMAC verification passed\n");

    // Decrypt the data using the SAME key as encryption
    mbedtls_aes_context aes_ctx;
    mbedtls_aes_init(&aes_ctx);
    
    // Use the same key (aes_key) that encrypt_message uses
    ret = mbedtls_aes_setkey_dec(&aes_ctx, ctx->aes_key, AES_KEY_SIZE * 8);
    if (ret != 0) {
        printf("DEBUG: AES decrypt key setup failed: %d\n", ret);
        mbedtls_aes_free(&aes_ctx);
        return -4;
    }
    
    uint8_t iv_copy[AES_IV_SIZE];
    memcpy(iv_copy, secure_msg->iv, AES_IV_SIZE);
    
    printf("DEBUG: AES decryption setup:\n");
    printf("  - Key length: %d bits\n", AES_KEY_SIZE * 8);
    printf("  - IV: ");
    for (int i = 0; i < AES_IV_SIZE; i++) {
        printf("%02x ", secure_msg->iv[i]);
    }
    printf("\n");
    printf("  - Padded length: %zu bytes\n", padded_len);
    
    uint8_t decrypted_padded[MAX_DATA_SIZE];
    ret = mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_DECRYPT, padded_len,
                                iv_copy, secure_msg->encrypted_data, decrypted_padded);
    
    mbedtls_aes_free(&aes_ctx);
    
    printf("DEBUG: AES decryption result: %d\n", ret);
    if (ret != 0) return -5;
    
    // Remove PKCS#7 padding
    size_t actual_len;
    ret = remove_pkcs7_padding(decrypted_padded, padded_len, &actual_len);
    if (ret != 0) {
        printf("DEBUG: Padding removal failed\n");
        return -6;
    }
    
    if (actual_len != secure_msg->data_length) {
        printf("DEBUG: Length mismatch: expected %u, got %zu\n", secure_msg->data_length, actual_len);
        return -7;
    }
    
    memcpy(decrypted_data, decrypted_padded, actual_len);
    *decrypted_len = actual_len;
    
    printf("DEBUG: decrypt_message completed successfully\n");
    return 0;
}

// Keep your existing functions for compatibility
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
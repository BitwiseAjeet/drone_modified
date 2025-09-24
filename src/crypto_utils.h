#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include "common.h"
#include <stdint.h>
#include <mbedtls/aes.h>
#include <mbedtls/md.h>
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/pkcs5.h"

#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define AES_IV_SIZE 16
#define MAX_DATA_SIZE 512
#define SERVER_PORT 8888
#define HMAC_SIZE 32
#define HMAC_KEY_SIZE 32

typedef struct {
    mbedtls_aes_context aes_ctx;
    uint8_t encryption_key[AES_KEY_SIZE];
    int initialized;
    mbedtls_md_context_t hmac_ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    uint8_t aes_key[AES_KEY_SIZE];
    uint8_t hmac_key[AES_KEY_SIZE];
    uint32_t sequence_number;
} crypto_context_t;

typedef struct {
    uint32_t message_id;
    uint32_t timestamp;
    uint32_t sequence_number;
    uint16_t data_length;
    uint8_t message_type;
    uint8_t reserved;
    uint8_t iv[AES_IV_SIZE];
    uint8_t encrypted_data[MAX_DATA_SIZE];
    uint8_t hmac[HMAC_SIZE];
} __attribute__((packed)) secure_message_t;

static int derive_keys(crypto_context_t* ctx, const char* password, const uint8_t* salt) {
    int ret;
    uint8_t derived_key[64]; // 32 bytes for AES + 32 bytes for HMAC

    // Use mbedTLS PBKDF2 function with proper MD context
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);

    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    ret = mbedtls_md_setup(&md_ctx, md_info, 1); // 1 for HMAC
    if (ret != 0) {
        mbedtls_md_free(&md_ctx);
        return ret;
    }

    // Use the newer PBKDF2 function
    ret = mbedtls_pkcs5_pbkdf2_hmac(&md_ctx,
                                    (const unsigned char*)password, strlen(password),
                                    salt, 16,
                                    10000,
                                    sizeof(derived_key), derived_key);

    mbedtls_md_free(&md_ctx);

    if (ret == 0) {
        memcpy(ctx->aes_key, derived_key, AES_KEY_SIZE);
        memcpy(ctx->hmac_key, derived_key + AES_KEY_SIZE, AES_KEY_SIZE);
    }

    // Clear derived key from memory
    memset(derived_key, 0, sizeof(derived_key));

    return ret;
}


int crypto_init(crypto_context_t* ctx,const char* password);
void crypto_cleanup(crypto_context_t* ctx);
int crypto_encrypt(crypto_context_t* ctx, const uint8_t* plaintext, 
                  size_t plaintext_len, uint8_t *ciphertext, size_t *ciphertext_len);
int crypto_decrypt(crypto_context_t* ctx, const uint8_t *ciphertext,
                  size_t ciphertext_len, uint8_t* plaintext, size_t* plaintext_len);  
static int derive_keys(crypto_context_t* ctx, const char* password, const uint8_t* salt);
int load_keys_from_file(crypto_context_t* ctx, const char* key_file);
int save_keys_to_file(const crypto_context_t* ctx, const char* key_file);
int encrypt_message(crypto_context_t* ctx, const uint8_t* data, size_t data_len, 
                   secure_message_t* secure_msg, uint8_t msg_type);
int decrypt_message(crypto_context_t* ctx, const secure_message_t* secure_msg, 
                   uint8_t* decrypted_data, size_t* decrypted_len);
#endif
//  int ret = decrypt_message(ctx, secure_msg, decrypted_data, &decrypted_len);
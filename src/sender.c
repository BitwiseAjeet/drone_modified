

#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    //#pragma comment(lib, "ws2_32.lib")
    typedef int socklen_t;
    #define close closesocket
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <pthread.h>
#endif

// Configuration constants
#define SERVER_PORT 8888
#define BUFFER_SIZE 2048
#define MAX_DATA_SIZE 512
#define AES_KEY_SIZE 32
#define AES_IV_SIZE 16
#define HMAC_SIZE 32
#define MAX_RETRIES 3

// Message types for drone communication
typedef enum {
    MSG_GPS_DATA = 0x01,
    MSG_IMU_DATA = 0x02,
    MSG_CONTROL_CMD = 0x03,
    MSG_STATUS_UPDATE = 0x04,
    MSG_EMERGENCY_STOP = 0x05,
    MSG_KEY_EXCHANGE = 0x06,
    MSG_HEARTBEAT = 0x07,
    MSG_ACK = 0x08
} message_type_t;

// Drone sensor data structures
typedef struct {
    double latitude;
    double longitude;
    double altitude;
    float speed;
    uint8_t satellites;
} gps_data_t;

typedef struct {
    float accel_x, accel_y, accel_z;
    float gyro_x, gyro_y, gyro_z;
    float mag_x, mag_y, mag_z;
    uint32_t timestamp;
} imu_data_t;

typedef struct {
    uint8_t throttle;
    int8_t pitch;
    int8_t roll;
    int8_t yaw;
    uint8_t mode;
} control_cmd_t;

// Secure message structure
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

// Function declarations
int init_network(void);
void cleanup_network(void);
uint32_t get_timestamp(void);
//void print_hex(const char* label, const uint8_t* data, size_t len);
//void log_message(const char* level, const char* format, ...);
int generate_random_bytes(uint8_t* buffer, size_t length);

#endif // COMMON_H

// ==================== common.c ====================
#include "common.h"
#include <stdarg.h>

//static uint32_t sequence_counter = 0
/*uint32_t get_timestamp(void) {
    return (uint32_t)time(NULL);
}*/

/*int init_network(void) {
#ifdef _WIN32
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (result != 0) {
        printf("WSAStartup failed: %d\n", result);
        return -1;
    }
#endif
    return 0;
}*/

/*void cleanup_network(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}*/

void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0) printf("\n    ");
        else if ((i + 1) % 4 == 0) printf(" ");
    }
    printf("\n");
}

void log_message(const char* level, const char* format, ...) {
    time_t rawtime;
    struct tm* timeinfo;
    char timestamp[64];

    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);

    printf("[%s] [%s] ", timestamp, level);

    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    printf("\n");
}

int generate_random_bytes(uint8_t* buffer, size_t length) {
    // Simple random number generation - in production use hardware RNG
    static int seeded = 0;
    if (!seeded) {
        srand((unsigned int)time(NULL));
        seeded = 1;
    }

    for (size_t i = 0; i < length; i++) {
        buffer[i] = rand() & 0xFF;
    }
    return 0;
}

// ==================== crypto_utils.h ====================
#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include "common.h"
#include "mbedtls/aes.h"
#include "mbedtls/md.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/pkcs5.h"

typedef struct {
    mbedtls_aes_context aes_ctx;
    mbedtls_md_context_t hmac_ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    uint8_t aes_key[AES_KEY_SIZE];
    uint8_t hmac_key[AES_KEY_SIZE];
    uint32_t sequence_number;
} crypto_context_t;

// Function declarations
int crypto_init(crypto_context_t* ctx, const char* password);
void crypto_cleanup(crypto_context_t* ctx);
int encrypt_message(crypto_context_t* ctx, const uint8_t* plaintext, 
                   size_t plaintext_len, secure_message_t* secure_msg, 
                   uint8_t msg_type);
int decrypt_message_sender(crypto_context_t* ctx, const secure_message_t* secure_msg, 
                   uint8_t* plaintext, size_t* plaintext_len);
int load_keys_from_file(crypto_context_t* ctx, const char* key_file);
int save_keys_to_file(const crypto_context_t* ctx, const char* key_file);
int derive_keys(crypto_context_t* ctx, const char* password, const uint8_t* salt);

#endif // CRYPTO_UTILS_H

// ==================== crypto_utils.c ====================
#include "crypto_utils.h"

//static const char* CRYPTO_SEED = "drone_security_2024";




/*int derive_keys(crypto_context_t* ctx, const char* password, const uint8_t* salt) {
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
}*/

/*int encrypt_message(crypto_context_t* ctx, const uint8_t* plaintext, 
                   size_t plaintext_len, secure_message_t* secure_msg, 
                   uint8_t msg_type) {
    int ret = 0;

    // Initialize message header
    secure_msg->message_id = rand();
    secure_msg->timestamp = get_timestamp();
    secure_msg->sequence_number = ++ctx->sequence_number;
    secure_msg->message_type = msg_type;
    secure_msg->data_length = (uint16_t)plaintext_len;
    secure_msg->reserved = 0;

    // Generate random IV
    ret = mbedtls_ctr_drbg_random(&ctx->ctr_drbg, secure_msg->iv, AES_IV_SIZE);
    if (ret != 0) {
        log_message("ERROR", "IV generation failed: %d", ret);
        return ret;
    }

    // Pad plaintext to AES block size
    size_t padded_len = ((plaintext_len + 15) / 16) * 16;
    uint8_t padded_plaintext[MAX_DATA_SIZE];
    memcpy(padded_plaintext, plaintext, plaintext_len);

    // PKCS#7 padding
    uint8_t pad_value = (uint8_t)(padded_len - plaintext_len);
    for (size_t i = plaintext_len; i < padded_len; i++) {
        padded_plaintext[i] = pad_value;
    }

    // Encrypt using AES-CBC
    uint8_t iv_copy[AES_IV_SIZE];
    memcpy(iv_copy, secure_msg->iv, AES_IV_SIZE);

    ret = mbedtls_aes_crypt_cbc(&ctx->aes_ctx, MBEDTLS_AES_ENCRYPT, 
                                padded_len, iv_copy, padded_plaintext, 
                                secure_msg->encrypted_data);
    if (ret != 0) {
        log_message("ERROR", "AES encryption failed: %d", ret);
        return ret;
    }

    // Calculate HMAC over entire message (except HMAC field)
    mbedtls_md_hmac_reset(&ctx->hmac_ctx);
    mbedtls_md_hmac_update(&ctx->hmac_ctx, (uint8_t*)secure_msg, 
                           sizeof(secure_message_t) - HMAC_SIZE);
    mbedtls_md_hmac_finish(&ctx->hmac_ctx, secure_msg->hmac);

    log_message("DEBUG", "Message encrypted successfully (ID: %u, Seq: %u)", 
                secure_msg->message_id, secure_msg->sequence_number);

    return 0;
}*/

int decrypt_message_sender(crypto_context_t* ctx, const secure_message_t* secure_msg, 
                   uint8_t* plaintext, size_t* plaintext_len) {
    int ret = 0;
    uint8_t computed_hmac[HMAC_SIZE];

    // Verify HMAC
    mbedtls_md_hmac_reset(&ctx->hmac_ctx);
    mbedtls_md_hmac_update(&ctx->hmac_ctx, (uint8_t*)secure_msg, 
                           sizeof(secure_message_t) - HMAC_SIZE);
    mbedtls_md_hmac_finish(&ctx->hmac_ctx, computed_hmac);

    if (memcmp(computed_hmac, secure_msg->hmac, HMAC_SIZE) != 0) {
        log_message("ERROR", "HMAC verification failed - message integrity compromised");
        return -1;
    }

    // Check sequence number for replay protection
    if (secure_msg->sequence_number <= ctx->sequence_number) {
        log_message("WARNING", "Possible replay attack detected (seq: %u <= %u)", 
                    secure_msg->sequence_number, ctx->sequence_number);
        
    }
    ctx->sequence_number = secure_msg->sequence_number;

    // Decrypt message
    size_t encrypted_len = ((secure_msg->data_length + 15) / 16) * 16;
    uint8_t decrypted_data[MAX_DATA_SIZE];
    uint8_t iv_copy[AES_IV_SIZE];
    memcpy(iv_copy, secure_msg->iv, AES_IV_SIZE);

    mbedtls_aes_context decrypt_ctx;
    mbedtls_aes_init(&decrypt_ctx);
    ret = mbedtls_aes_setkey_dec(&decrypt_ctx, ctx->aes_key, AES_KEY_SIZE * 8);
    if (ret != 0) {
        mbedtls_aes_free(&decrypt_ctx);
        log_message("ERROR", "AES decrypt key setup failed: %d", ret);
        return ret;
    }

    ret = mbedtls_aes_crypt_cbc(&decrypt_ctx, MBEDTLS_AES_DECRYPT, 
                                encrypted_len, iv_copy, secure_msg->encrypted_data, 
                                decrypted_data);
    mbedtls_aes_free(&decrypt_ctx);

    if (ret != 0) {
        log_message("ERROR", "AES decryption failed: %d", ret);
        return ret;
    }

    // Remove PKCS#7 padding
    uint8_t pad_value = decrypted_data[secure_msg->data_length - 1];
    if (pad_value > 16 || pad_value == 0) {
        log_message("ERROR", "Invalid padding detected");
        return -1;
    }

    *plaintext_len = secure_msg->data_length;
    memcpy(plaintext, decrypted_data, secure_msg->data_length);

    log_message("DEBUG", "Message decrypted successfully (ID: %u, Type: %u)", 
                secure_msg->message_id, secure_msg->message_type);

    return 0;
}

// ==================== sender.c ====================
#include "common.h"
#include "crypto_utils.h"

crypto_context_t crypto_ctx;
 int client_socket = -1;

void cleanup_sender(void) {
    if (client_socket >= 0) {
        close(client_socket);
    }
    crypto_cleanup(&crypto_ctx);
    cleanup_network();
}

int send_secure_message(const uint8_t* data, size_t data_len, uint8_t msg_type) {
    secure_message_t secure_msg;
    int ret;
    
    // Encrypt the message
    ret = encrypt_message(&crypto_ctx, data, data_len, &secure_msg, msg_type);
    if (ret != 0) {
        log_message("ERROR", "Message encryption failed");
        return ret;
    }
    
    // Send encrypted message
     int sent = send(client_socket, (char*)&secure_msg, sizeof(secure_msg), 0);
    if (sent < 0) {
        log_message("ERROR", "Failed to send message: %s", strerror(errno));
        return -1;
    }
    log_message("DEBUG", "Encrypted message data:");
    for (size_t i = 0; i < secure_msg.data_length; i++) {
    if (i % 16 == 0) printf("\n");
    printf("%02X ", secure_msg.encrypted_data[i]);
    }
    printf("\n");

    log_message("INFO", "Sent %s message (ID: %u, %zu bytes)", 
                msg_type == MSG_GPS_DATA ? "GPS" :
                msg_type == MSG_IMU_DATA ? "IMU" :
                msg_type == MSG_CONTROL_CMD ? "CONTROL" :
                msg_type == MSG_STATUS_UPDATE ? "STATUS" :
                msg_type == MSG_HEARTBEAT ? "HEARTBEAT" : "UNKNOWN",
                secure_msg.message_id, sent);
    
    return 0;
}

int send_gps_data(void) {
    gps_data_t gps_data = {
        .latitude = 28.6139 + (rand() % 1000) / 100000.0,   // Patna area
        .longitude = 85.1406 + (rand() % 1000) / 100000.0,
        .altitude = 50.0 + (rand() % 100),
        .speed = 15.5 + (rand() % 50) / 10.0,
        .satellites = 8 + (rand() % 5)
    };
    
    return send_secure_message((uint8_t*)&gps_data, sizeof(gps_data), MSG_GPS_DATA);
}

int send_imu_data(void) {
    imu_data_t imu_data = {
        .accel_x = (rand() % 2000 - 1000) / 100.0,
        .accel_y = (rand() % 2000 - 1000) / 100.0,
        .accel_z = (rand() % 2000 - 1000) / 100.0,
        .gyro_x = (rand() % 360) / 10.0,
        .gyro_y = (rand() % 360) / 10.0,
        .gyro_z = (rand() % 360) / 10.0,
        .mag_x = (rand() % 1000) / 10.0,
        .mag_y = (rand() % 1000) / 10.0,
        .mag_z = (rand() % 1000) / 10.0,
        .timestamp = get_timestamp()
    };
    
    return send_secure_message((uint8_t*)&imu_data, sizeof(imu_data), MSG_IMU_DATA);
}

int send_heartbeat(void) {
    uint32_t heartbeat_data = get_timestamp();
    return send_secure_message((uint8_t*)&heartbeat_data, sizeof(heartbeat_data), MSG_HEARTBEAT);
}

int connect_to_server(const char* server_ip) {
    struct sockaddr_in server_addr;
    
    // Create socket
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket < 0) {
        log_message("ERROR", "Socket creation failed: %s", strerror(errno));
        return -1;
    }
    
    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        log_message("ERROR", "Invalid server IP address: %s", server_ip);
        close(client_socket);
        client_socket = -1;
        return -1;
    }
    
    // Connect to server with retries
    int retries = 0;
    while (retries < MAX_RETRIES) {
        if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == 0) {
            log_message("INFO", "Connected to server %s:%d", server_ip, SERVER_PORT);
            return 0;
        }
        
        retries++;
        log_message("WARNING", "Connection attempt %d failed: %s", retries, strerror(errno));
        
        if (retries < MAX_RETRIES) {
            Sleep(2); // Wait 2 seconds before retry
        }
    }
    
    log_message("ERROR", "Failed to connect after %d attempts", MAX_RETRIES);
    close(client_socket);
    client_socket = -1;
    return -1;
}

int main(int argc, char* argv[]) {
    const char* server_ip = "127.0.0.1";
    const char* password = "drone_secure_2024";
    
    if (argc > 1) {
        server_ip = argv[1];
    }
    if (argc > 2) {
        password = argv[2];
    }
    
    log_message("INFO", "Starting secure drone sender...");
    
    // Initialize network
    if (init_network() != 0) {
        log_message("ERROR", "Network initialization failed");
        return 1;
    }
    printf ("this is a degug log for network initialization");
    // Initialize crypto
    if (crypto_init(&crypto_ctx, password) != 0) {
        log_message("ERROR", "Crypto initialization failed");
        cleanup_network();
        return 1;
    }
 printf ("this is a degug log for crypto initialization");
    // Setup cleanup handler
    atexit(cleanup_sender);
    
    // Connect to server
    if (connect_to_server(server_ip) != 0) {
        return 1;
    }
     printf ("this is a degug log for server initialization");
    log_message("INFO", "Drone sender initialized successfully");
    
    // Main transmission loop
    int cycle = 0;
    while (1) {
        // Send GPS data every cycle 
        if (send_gps_data() != 0) {
            log_message("ERROR", "Failed to send GPS data");
            break;
        }
        
        // Send IMU data every cycle
        if (send_imu_data() != 0) {
            log_message("ERROR", "Failed to send IMU data");
            break;
        }
        
        // Send heartbeat every 10 cycles
        if (cycle % 10 == 0) {
            if (send_heartbeat() != 0) {
                log_message("ERROR", "Failed to send heartbeat");
                break;
            }
        }
        
        cycle++;
         printf ("this is a degug log for transmission check");
        // Wait 1 second between transmissions
#ifdef _WIN32
        Sleep(1000);
#else
        sleep(1);
#endif
    }
    
    return 0;
}
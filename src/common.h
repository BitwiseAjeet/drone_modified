#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <stdbool.h>
#include <stdarg.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <windows.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    #define Sleep(x) Sleep(x)
    #define close(x) closesocket(x)
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <netdb.h>
    #define Sleep(x) usleep((x)*1000)
    typedef int SOCKET;
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
#endif

// Fallback include path from existing version
#include "mavlink.h"

// Port and buffer definitions - keeping both for compatibility
#define SERVER_PORT 
#define DEFAULT_PORT 8080
#define BUFFER_SIZE 1024
#define MAX_RETRIES 3
#define MAX_DATA_SIZE 512
#define MAX_MESSAGE_SIZE 512

// Encryption and security definitions
#define AES_IV_SIZE 16
#define HMAC_SIZE 32

// Custom MAVLink command for fingerprint confirmation
#define MAV_CMD_FINGERPRINT_CONFIRM 40001  // Custom user command

// Combined message types enum - incorporating all types from both files
typedef enum {
    // From existing file
    MSG_STATUS = 2,
    MSG_COMMAND = 3,
    MSG_TELEMETRY = 4,
    
    // Common types (using hex values from new file for consistency)
    MSG_GPS_DATA = 0x01,
    MSG_IMU_DATA = 0x02,
    MSG_HEARTBEAT = 0x03,       // Updated to use new file's value
    MSG_CONTROL_CMD = 0x04,     // Updated to use new file's value
    MSG_STATUS_UPDATE = 0x05,   // Updated to use new file's value
    MSG_EMERGENCY_STOP = 0x06,  // Updated to use new file's value
    MSG_KEY_EXCHANGE = 0x07,    // Updated to use new file's value
    MSG_ACK = 0x08,
    MSG_FINGERPRINT_CONFIRM = 0x09  // New type from new file
} message_type_t;

// Existing drone message structure
typedef struct {
    message_type_t type;
    uint32_t timestamp;
    uint16_t sequence;
    uint16_t payload_size;
    uint8_t payload[MAX_MESSAGE_SIZE];
} drone_message_t;

// Existing GPS data structure
typedef struct {
    double latitude;
    double longitude;
    double altitude;
    float speed;
    uint8_t satellites;
} gps_data_t;

// Existing IMU data structure
typedef struct {
    float accel_x, accel_y, accel_z;
    float gyro_x, gyro_y, gyro_z;
    float mag_x, mag_y, mag_z;
    uint32_t timestamp;
} imu_data_t;

// New secure MAVLink wrapper structure
typedef struct {
    uint32_t message_id;        // Random message ID
    uint32_t timestamp;         // Unix timestamp
    uint32_t sequence_number;   // Sequence counter
    uint16_t inner_length;      // Length of original MAVLink packet
    uint8_t message_type;       // Internal message type for tracking
    uint8_t reserved;           // Reserved byte
    uint8_t iv[AES_IV_SIZE];    // AES initialization vector
    uint8_t encrypted_data[MAX_DATA_SIZE];  // Encrypted MAVLink packet
    uint8_t hmac[HMAC_SIZE];    // HMAC for authentication
} secure_mavlink_t;

// New fingerprint confirmation data structure
typedef struct {
    uint8_t system_id;
    uint8_t component_id;
    uint8_t match_confirmed;    // 1 for match, 0 for no match
    uint32_t timestamp;
    uint8_t reserved[3];        // Padding for alignment
} fingerprint_confirm_t;

// Function declarations - combining all functions from both files
// Network functions
int init_network(void);
void cleanup_network(void);

// Utility functions
uint32_t get_timestamp(void);
void log_message(const char* level, const char* format, ...);
void print_hex(const char* prefix, const uint8_t* data, size_t len);
void print_message(const drone_message_t *msg);  // From existing file

// MAVLink utility functions (from new file)
uint16_t mavlink_crc_calculate(const uint8_t *buffer, size_t length);
void mavlink_crc_accumulate(uint16_t *crc, uint8_t data);
int pack_outer_mavlink(uint8_t sysid, uint8_t compid, uint32_t msgid, 
                      const uint8_t* payload, uint8_t payload_len, 
                      uint8_t* packet, size_t* packet_len);

#endif // COMMON_H
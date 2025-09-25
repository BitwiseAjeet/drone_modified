#include "common.h"
#include "crypto_utils.h"

#ifdef _WIN32
    #include <windows.h>
#else
    #include <signal.h>
#endif

#define SERVER_PORT 8888  // MAVLink standard UDP port
#define BUFFER_SIZE 1024
#define MAX_PAYLOAD_LEN 255

static crypto_context_t crypto_ctx;
static int udp_socket = -1;
static volatile int running = 1;

// MAVLink message structure for parsing
typedef struct {
    uint8_t sys_id;
    uint8_t comp_id;
    uint32_t msg_id;
    uint8_t payload[MAX_PAYLOAD_LEN];
    uint8_t payload_len;
} mavlink_message_t1;

// Function to calculate MAVLink CRC
uint16_t mavlink_crc_calculate(const uint8_t *buffer, size_t length) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < length; i++) {
        uint8_t tmp = buffer[i] ^ (uint8_t)(crc & 0xFF);
        tmp ^= (tmp << 4);
        crc = (crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4);
    }
    return crc;
}

// Parse MAVLink v2 packet
int parse_mavlink(const uint8_t *buffer, size_t len, mavlink_message_t1 *msg) {
    if (len < 12 || buffer[0] != 0xFD) {
        return -1; // Invalid magic or too short
    }

    uint8_t payload_len = buffer[1];
    uint8_t incompat_flags = buffer[2];
    uint8_t compat_flags = buffer[3];
    // buffer[4] seq
    uint8_t sys_id = buffer[5];
    uint8_t comp_id = buffer[6];
    uint32_t msg_id = buffer[7] | (buffer[8] << 8) | (buffer[9] << 16);

    if (len < 12 + payload_len) {
        return -1; // Incomplete packet
    }

    // Calculate CRC over len to payload
    uint16_t crc_calc = mavlink_crc_calculate(&buffer[1], 9 + payload_len);
    uint8_t crc_extra = 0; // For custom messages
    uint16_t tmp_crc = crc_calc;
    uint8_t low = crc_extra ^ (tmp_crc & 0xff);
    low ^= (low << 4);
    tmp_crc = (tmp_crc >> 8) ^ (low << 8) ^ (low << 3) ^ (low >> 4);
    crc_calc = tmp_crc;

    uint16_t crc_received = buffer[10 + payload_len] | (buffer[11 + payload_len] << 8);

    if (crc_calc != crc_received) {
        log_message("ERROR", "MAVLink CRC mismatch: calc=0x%04X received=0x%04X", crc_calc, crc_received);
        return -1;
    }

    msg->sys_id = sys_id;
    msg->comp_id = comp_id;
    msg->msg_id = msg_id;
    msg->payload_len = payload_len;
    memcpy(msg->payload, &buffer[10], payload_len);

    return 0;
}

void handle_signal(int sig) {
    log_message("INFO", "Received signal %d, shutting down...", sig);
    running = 0;
}

void cleanup_receiver(void) {
    running = 0;
    if (udp_socket >= 0) {
        close(udp_socket);
    }
    crypto_cleanup(&crypto_ctx);
    cleanup_network();
}

void process_gps_data(const gps_data_t* gps) {
    log_message("INFO", "GPS Data - Lat: %.6f, Lon: %.6f, Alt: %.1fm, Speed: %.1fkm/h, Sats: %d",
                gps->latitude, gps->longitude, gps->altitude, gps->speed, gps->satellites);
}

void process_imu_data(const imu_data_t* imu) {
    log_message("INFO", "IMU Data - Accel(%.2f,%.2f,%.2f) Gyro(%.1f,%.1f,%.1f) Mag(%.1f,%.1f,%.1f)",
                imu->accel_x, imu->accel_y, imu->accel_z,
                imu->gyro_x, imu->gyro_y, imu->gyro_z,
                imu->mag_x, imu->mag_y, imu->mag_z);
}

void process_heartbeat(const uint32_t* timestamp) {
    log_message("INFO", "Heartbeat received - Timestamp: %u", *timestamp);
}

void log_message(const char* level, const char* format, ...) {
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    char time_str[20];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    
    printf("[%s] %s: ", time_str, level);
    
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    
    printf("\n");
    fflush(stdout);
}

void print_hex(const char* prefix, const uint8_t* data, size_t len) {
    if (prefix && strlen(prefix) > 0) {
        printf("%s", prefix);
    }
    
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (len % 16 != 0) printf("\n");
    fflush(stdout);
    }


int process_secure_message(crypto_context_t* ctx, const secure_message_t* secure_msg) {
    uint8_t decrypted_data[MAX_DATA_SIZE];
    size_t decrypted_len;

    int ret = decrypt_message(ctx, secure_msg, decrypted_data,&decrypted_len );
    if (ret != 0) {
        log_message("ERROR", "Message decryption failed: %d", ret);
        return ret;
    }

    // Process based on message type
    switch (secure_msg->message_type) {
        case MSG_GPS_DATA:
            if (decrypted_len == sizeof(gps_data_t)) {
                process_gps_data((gps_data_t*)(decrypted_data));
            } else {
                log_message("ERROR", "Invalid GPS data size: %zu", decrypted_len);
            }
            break;
        case MSG_IMU_DATA:
            if (decrypted_len == sizeof(imu_data_t)) {
                process_imu_data((imu_data_t*)decrypted_data);
            } else {
                log_message("ERROR", "Invalid IMU data size: %zu", decrypted_len);
            }
            break;
        case MSG_HEARTBEAT:
            if (decrypted_len == sizeof(uint32_t)) {
                process_heartbeat((uint32_t*)decrypted_data);
            } else {
                log_message("ERROR", "Invalid heartbeat data size: %zu", decrypted_len);
            }
            break;
        case MSG_CONTROL_CMD:
            log_message("INFO", "Control command received");
            break;
        case MSG_STATUS_UPDATE:
            log_message("INFO", "Status update received");
            break;
        case MSG_EMERGENCY_STOP:
            log_message("CRITICAL", "EMERGENCY STOP received!");
            break;
        default:
            log_message("WARNING", "Unknown message type: %u", secure_msg->message_type);
            break;
    }

    return 0;
}

int main(int argc, char* argv[]) {
    const char* password = "drone_secure_2024";

    if (argc > 1) {
        password = argv[1];
    }

    log_message("INFO", "Starting secure drone MAVLink receiver...");

#ifndef _WIN32
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
#endif

    if (init_network() != 0) {
        log_message("ERROR", "Network initialization failed");
        return 1;
    }

    if (crypto_init(&crypto_ctx, password) != 0) {
        log_message("ERROR", "Crypto initialization failed");
        cleanup_network();
        return 1;
    }

    atexit(cleanup_receiver);

    // Create UDP socket
    udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_socket < 0) {
        log_message("ERROR", "UDP socket creation failed: %s", strerror(errno));
        return 1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SERVER_PORT);

    if (bind(udp_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        log_message("ERROR", "Bind failed: %s", strerror(errno));
        close(udp_socket);
        return 1;
    }

    log_message("INFO", "Receiver listening on UDP port %d", SERVER_PORT);

    uint8_t buffer[BUFFER_SIZE];
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    while (running) {
        ssize_t received = recvfrom(udp_socket, buffer, BUFFER_SIZE, 0, 
                                    (struct sockaddr*)&client_addr, &client_len);
        if (received < 0) {
            if (running) {
                log_message("ERROR", "Recv failed: %s", strerror(errno));
            }
            continue;
        }

        mavlink_message_t1 msg;
        if (parse_mavlink(buffer, (size_t)received, &msg) != 0) {
            log_message("WARNING", "Invalid MAVLink packet received (%zd bytes)", received);
            continue;
        }

        if (msg.msg_id < 200 || msg.msg_id > 255) {
            log_message("DEBUG", "Non-custom MAVLink message ID %u ignored", msg.msg_id);
            continue;
        }

        log_message("DEBUG", "Received custom MAVLink msg ID %u, payload %u bytes from sys %u comp %u", 
                    msg.msg_id, msg.payload_len, msg.sys_id, msg.comp_id);

        // Reconstruct secure_message_t from payload
        secure_message_t secure_msg = {0};
        const uint8_t* ptr = msg.payload;

        secure_msg.message_id = *(uint32_t*)ptr; ptr += 4;
        secure_msg.timestamp = *(uint32_t*)ptr; ptr += 4;
        secure_msg.sequence_number = *(uint32_t*)ptr; ptr += 4;
        secure_msg.data_length = *(uint16_t*)ptr; ptr += 2;
        secure_msg.message_type = *ptr; ptr += 1;
        secure_msg.reserved = *ptr; ptr += 1;
        memcpy(secure_msg.iv, ptr, AES_IV_SIZE); ptr += AES_IV_SIZE;

        size_t padded_len = ((secure_msg.data_length + 15) / 16) * 16;
        if (msg.payload_len != (4+4+4+2+1+1+AES_IV_SIZE + padded_len + HMAC_SIZE)) {
            log_message("ERROR", "Invalid payload length for secure message: %u (expected %zu)", 
                        msg.payload_len, (4+4+4+2+1+1+AES_IV_SIZE + padded_len + HMAC_SIZE));
            continue;
        }

        memcpy(secure_msg.encrypted_data, ptr, padded_len); ptr += padded_len;
        memcpy(secure_msg.hmac, ptr, HMAC_SIZE);

        // Process the secure message
        if (process_secure_message(&crypto_ctx, &secure_msg) != 0) {
            log_message("ERROR", "Failed to process secure message");
        }
    }

    log_message("INFO", "Receiver shutting down...");
    return 0;
}
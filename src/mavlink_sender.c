#include "common.h"
#include "crypto_utils.h"

crypto_context_t crypto_ctx;
int client_socket = -1;
struct sockaddr_in server_addr;

// MAVLink CRC functions
uint16_t mavlink_crc_calculate(const uint8_t *buffer, size_t length) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < length; i++) {
        uint8_t tmp = buffer[i] ^ (uint8_t)(crc & 0xFF);
        tmp ^= (tmp << 4);
        crc = (crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4);
    }
    return crc;
}

void mavlink_crc_accumulate(uint16_t *crc, uint8_t data) {
    uint8_t tmp = data ^ (uint8_t)(*crc & 0xFF);
    tmp ^= (tmp << 4);
    *crc = (*crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4);
}

// Pack MAVLink custom message
int pack_mavlink_custom(uint8_t sysid, uint8_t compid, uint32_t msgid, 
                        const uint8_t* payload, uint8_t payload_len, 
                        uint8_t* packet, size_t* packet_len) {
    if (payload_len > 255) return -1;

    static uint8_t seq = 0;
    uint8_t current_seq = seq++;

    packet[0] = 0xFD;  // v2 magic
    packet[1] = payload_len;
    packet[2] = 0;  // incompat flags
    packet[3] = 0;  // compat flags
    packet[4] = current_seq;
    packet[5] = sysid;
    packet[6] = compid;
    packet[7] = msgid & 0xFF;
    packet[8] = (msgid >> 8) & 0xFF;
    packet[9] = (msgid >> 16) & 0xFF;
    memcpy(&packet[10], payload, payload_len);

    uint16_t crc = mavlink_crc_calculate(&packet[1], 9 + payload_len);
    uint8_t crc_extra = 0;
    mavlink_crc_accumulate(&crc, crc_extra);

    packet[10 + payload_len] = crc & 0xFF;
    packet[11 + payload_len] = (crc >> 8) & 0xFF;

    *packet_len = 12 + payload_len;
    return 0;
}



void cleanup_sender(void) {
    if (client_socket >= 0) {
        close(client_socket);
    }
    crypto_cleanup(&crypto_ctx);
    cleanup_network();
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

int init_udp_sender(const char* server_ip) {
    client_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (client_socket < 0) {
        log_message("ERROR", "Socket creation failed: %s", strerror(errno));
        return -1;
    }

    // Enable broadcast if needed
    // int broadcast = 1;
    // setsockopt(client_socket, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);

    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        log_message("ERROR", "Invalid server IP: %s", server_ip);
        close(client_socket);
        client_socket = -1;
        return -1;
    }

    log_message("INFO", "UDP sender initialized for %s:%d", server_ip, SERVER_PORT);
    return 0;
}

int send_secure_message(const uint8_t* data, size_t data_len, uint8_t msg_type) {
    secure_message_t secure_msg;
    int ret = encrypt_message(&crypto_ctx, data, data_len, &secure_msg, msg_type);
    if (ret != 0) {
        log_message("ERROR", "Encryption failed");
        return ret;
    }

    size_t padded_len = ((data_len + 15) / 16) * 16;

    uint8_t secure_buffer[1024];
    size_t secure_len = 0;
    memcpy(secure_buffer + secure_len, &secure_msg.message_id, 4); secure_len += 4;
    memcpy(secure_buffer + secure_len, &secure_msg.timestamp, 4); secure_len += 4;
    memcpy(secure_buffer + secure_len, &secure_msg.sequence_number, 4); secure_len += 4;
    memcpy(secure_buffer + secure_len, &secure_msg.data_length, 2); secure_len += 2;
    memcpy(secure_buffer + secure_len, &secure_msg.message_type, 1); secure_len += 1;
    memcpy(secure_buffer + secure_len, &secure_msg.reserved, 1); secure_len += 1;
    memcpy(secure_buffer + secure_len, secure_msg.iv, AES_IV_SIZE); secure_len += AES_IV_SIZE;
    memcpy(secure_buffer + secure_len, secure_msg.encrypted_data, padded_len); secure_len += padded_len;
    memcpy(secure_buffer + secure_len, secure_msg.hmac, HMAC_SIZE); secure_len += HMAC_SIZE;

    if (secure_len > 255) {
        log_message("ERROR", "Payload too large: %zu bytes", secure_len);
        return -1;
    }

    uint8_t mav_packet[512];
    size_t mav_len;
    uint32_t mav_msgid = 200 + msg_type;
    ret = pack_mavlink_custom(255, 0, mav_msgid, secure_buffer, (uint8_t)secure_len, mav_packet, &mav_len);
    if (ret != 0) {
        log_message("ERROR", "MAVLink packing failed");
        return ret;
    }

    int attempts = 0;
    ssize_t sent = -1;
    while (attempts < MAX_RETRIES && sent < 0) {
        sent = sendto(client_socket, (char*)mav_packet, mav_len, 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
        if (sent < 0) {
            log_message("WARNING", "Send attempt %d failed: %s", attempts + 1, strerror(errno));
            Sleep(200);
        }
        attempts++;
    }

    if (sent < 0) {
        log_message("ERROR", "Failed to send after %d retries", MAX_RETRIES);
        return -1;
    }

    log_message("DEBUG", "Encrypted message data:");
    print_hex("", secure_msg.encrypted_data, padded_len);

    log_message("INFO", "Sent %s message (ID: %u, %zd bytes)", 
                msg_type == MSG_GPS_DATA ? "GPS" :
                msg_type == MSG_IMU_DATA ? "IMU" :
                msg_type == MSG_HEARTBEAT ? "HEARTBEAT" : "UNKNOWN",
                secure_msg.message_id, sent);

    return 0;
}

int send_gps_data(void) {
    gps_data_t gps_data = {
        .latitude = 28.6139 + (rand() % 1000) / 100000.0,
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

    if (init_network() != 0) {
        log_message("ERROR", "Network initialization failed");
        return 1;
    }
    printf("this is a debug log for network initialization\n");

    if (crypto_init(&crypto_ctx, password) != 0) {
        log_message("ERROR", "Crypto initialization failed");
        cleanup_network();
        return 1;
    }
    printf("this is a debug log for crypto initialization\n");

    atexit(cleanup_sender);

    if (init_udp_sender(server_ip) != 0) {
        return 1;
    }
    printf("this is a debug log for server initialization\n");

    log_message("INFO", "Drone sender initialized successfully");

    int cycle = 0;
    while (1) {
        if (send_gps_data() != 0) {
            log_message("ERROR", "Failed to send GPS data");
            break;
        }

        if (send_imu_data() != 0) {
            log_message("ERROR", "Failed to send IMU data");
            break;
        }

        if (cycle % 10 == 0) {
            if (send_heartbeat() != 0) {
                log_message("ERROR", "Failed to send heartbeat");
                break;
            }
        }

        cycle++;
        printf("this is a debug log for transmission check\n");
        Sleep(1000);
    }

    return 0;
}

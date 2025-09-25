#include "common.h"
#include "crypto_utils.h"

crypto_context_t crypto_ctx;
int client_socket = -1;
struct sockaddr_in server_addr;

// Outer MAVLink packet functions (for encrypted tunnel)
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

int pack_outer_mavlink(uint8_t sysid, uint8_t compid, uint32_t msgid, 
                      const uint8_t* payload, uint8_t payload_len, 
                      uint8_t* packet, size_t* packet_len) {
    if (payload_len > 255) return -1;

    static uint8_t seq = 0;
    uint8_t current_seq = seq++;

    packet[0] = 0xFD;  // MAVLink v2 magic
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
    uint8_t crc_extra = 0;  // For custom encrypted tunnel message
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



// Send encrypted standard MAVLink packet
int send_secure_mavlink(mavlink_message_t* inner_msg, uint8_t msg_type) {
    // Step 1: Serialize standard MAVLink message to buffer
    uint8_t inner_buffer[MAVLINK_MAX_PACKET_LEN];
    uint16_t inner_len = mavlink_msg_to_send_buffer(inner_buffer, inner_msg);
    
    log_message("DEBUG", "Standard MAVLink packet created (ID: %u, Length: %u)", 
                inner_msg->msgid, inner_len);
    print_hex("Inner MAVLink: ", inner_buffer, inner_len);

    // Step 2: Create secure wrapper
    secure_mavlink_t secure_msg = {0};
    secure_msg.message_id = rand();  // Random ID for tracking
    secure_msg.timestamp = get_timestamp();
    secure_msg.sequence_number = crypto_ctx.sequence_number++;
    secure_msg.inner_length = inner_len;
    secure_msg.message_type = msg_type;
    secure_msg.reserved = 0;

    // Step 3: Encrypt the standard MAVLink packet
    int ret = encrypt_message(&crypto_ctx, inner_buffer, inner_len, 
                             (secure_message_t*)&secure_msg, msg_type);
    if (ret != 0) {
        log_message("ERROR", "Encryption failed: %d", ret);
        return ret;
    }

    // Step 4: Serialize secure wrapper for outer MAVLink
    size_t padded_len = ((inner_len + 15) / 16) * 16;
    uint8_t secure_buffer[1024];
    size_t secure_len = 0;
    
    memcpy(secure_buffer + secure_len, &secure_msg.message_id, 4); secure_len += 4;
    memcpy(secure_buffer + secure_len, &secure_msg.timestamp, 4); secure_len += 4;
    memcpy(secure_buffer + secure_len, &secure_msg.sequence_number, 4); secure_len += 4;
    memcpy(secure_buffer + secure_len, &secure_msg.inner_length, 2); secure_len += 2;
    memcpy(secure_buffer + secure_len, &secure_msg.message_type, 1); secure_len += 1;
    memcpy(secure_buffer + secure_len, &secure_msg.reserved, 1); secure_len += 1;
    memcpy(secure_buffer + secure_len, secure_msg.iv, AES_IV_SIZE); secure_len += AES_IV_SIZE;
    memcpy(secure_buffer + secure_len, secure_msg.encrypted_data, padded_len); secure_len += padded_len;
    memcpy(secure_buffer + secure_len, secure_msg.hmac, HMAC_SIZE); secure_len += HMAC_SIZE;

    if (secure_len > 255) {
        log_message("ERROR", "Secure payload too large: %zu bytes", secure_len);
        return -1;
    }

    // Step 5: Wrap in outer MAVLink packet (encrypted tunnel)
    uint8_t outer_packet[512];
    size_t outer_len;
    uint32_t tunnel_msgid = 250;  // Custom message ID for encrypted tunnel
    
    ret = pack_outer_mavlink(255, 0, tunnel_msgid, secure_buffer, 
                            (uint8_t)secure_len, outer_packet, &outer_len);
    if (ret != 0) {
        log_message("ERROR", "Outer MAVLink packing failed");
        return ret;
    }

    // Step 6: Send with retries
    int attempts = 0;
    ssize_t sent = -1;
    while (attempts < MAX_RETRIES && sent < 0) {
        sent = sendto(client_socket, (char*)outer_packet, outer_len, 0, 
                     (struct sockaddr*)&server_addr, sizeof(server_addr));
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

    log_message("INFO", "Sent encrypted MAVLink (Inner ID: %u, Type: %s, %zd bytes)", 
                inner_msg->msgid,
                msg_type == MSG_GPS_DATA ? "GPS" :
                msg_type == MSG_IMU_DATA ? "IMU" :
                msg_type == MSG_HEARTBEAT ? "HEARTBEAT" :
                msg_type == MSG_FINGERPRINT_CONFIRM ? "FINGERPRINT" : "OTHER",
                sent);

    return 0;
}

// Send standard GPS_RAW_INT message
int send_gps_data(void) {
    mavlink_message_t msg;
    
    // Generate sample GPS data (replace with real sensor data)
    double lat = 28.6139 + (rand() % 1000) / 100000.0;
    double lon = 85.1406 + (rand() % 1000) / 100000.0;
    int32_t alt = 50000 + (rand() % 100000);  // mm above sea level
    uint16_t eph = 300;  // GPS HDOP
    uint16_t epv = 400;  // GPS VDOP
    uint16_t vel = 1550; // Ground speed cm/s
    int16_t vn = 100;    // GPS velocity north cm/s
    int16_t ve = 200;    // GPS velocity east cm/s
    int16_t vd = -10;    // GPS velocity down cm/s
    uint16_t cog = 18000; // Course over ground cdeg
    uint8_t satellites_visible = 8 + (rand() % 5);
    
    mavlink_msg_gps_raw_int_pack(255, 0, &msg,
                                get_timestamp() * 1000000ULL,  // time_usec
                                GPS_FIX_TYPE_3D_FIX,           // fix_type
                                (int32_t)(lat * 1e7),          // lat (degE7)
                                (int32_t)(lon * 1e7),          // lon (degE7)
                                alt,                           // alt (mm)
                                eph, epv, vel, cog,           // HDOP, VDOP, vel, cog
                                satellites_visible,            // satellites_visible
                                0,                            // alt_ellipsoid
                                0, 0, 0,                      // h_acc, v_acc, vel_acc
                                0, 0);                        // hdg_acc, yaw
    
    return send_secure_mavlink(&msg, MSG_GPS_DATA);
}

// Send standard ATTITUDE message
int send_imu_data(void) {
    mavlink_message_t msg;
    
    // Generate sample IMU data (replace with real sensor data)
    float roll = (rand() % 628 - 314) / 100.0f;    // ±3.14 rad
    float pitch = (rand() % 628 - 314) / 100.0f;   // ±3.14 rad
    float yaw = (rand() % 628) / 100.0f;           // 0-6.28 rad
    float rollspeed = (rand() % 200 - 100) / 100.0f;   // rad/s
    float pitchspeed = (rand() % 200 - 100) / 100.0f;  // rad/s
    float yawspeed = (rand() % 200 - 100) / 100.0f;    // rad/s
    
    mavlink_msg_attitude_pack(255, 0, &msg,
                             get_timestamp() * 1000,  // time_boot_ms
                             roll, pitch, yaw,        // roll, pitch, yaw (rad)
                             rollspeed, pitchspeed, yawspeed); // rollspeed, pitchspeed, yawspeed (rad/s)
    
    return send_secure_mavlink(&msg, MSG_IMU_DATA);
}

// Send standard HEARTBEAT message
int send_heartbeat(void) {
    mavlink_message_t msg;
    
    mavlink_msg_heartbeat_pack(255, 0, &msg,
                              MAV_TYPE_QUADROTOR,     // type
                              MAV_AUTOPILOT_PX4,      // autopilot
                              MAV_MODE_FLAG_SAFETY_ARMED, // base_mode
                              0,                      // custom_mode
                              MAV_STATE_ACTIVE);      // system_status
    
    return send_secure_mavlink(&msg, MSG_HEARTBEAT);
}

// Send fingerprint confirmation as COMMAND_LONG
int send_fingerprint_confirmation(uint8_t system_id, uint8_t match_confirmed) {
    mavlink_message_t msg;
    
    log_message("INFO", "Sending fingerprint confirmation (System: %u, Match: %u)", 
                system_id, match_confirmed);
    
    // Use COMMAND_LONG with custom command for fingerprint confirmation
    mavlink_msg_command_long_pack(255, 0, &msg,
                                 system_id,              // target_system
                                 0,                      // target_component
                                 MAV_CMD_FINGERPRINT_CONFIRM, // command
                                 0,                      // confirmation
                                 match_confirmed,        // param1: match status
                                 system_id,              // param2: system_id
                                 get_timestamp(),        // param3: timestamp
                                 0, 0, 0, 0);           // param4-7: reserved
    
    return send_secure_mavlink(&msg, MSG_FINGERPRINT_CONFIRM);
}

// Simulate UART read from fingerprint module
int read_fingerprint_uart(void) {
    // TODO: Replace with actual UART reading code for ESP32
    // For now, simulate fingerprint match every 20 cycles
    static int uart_cycle = 0;
    uart_cycle++;
    
    if (uart_cycle % 20 == 0) {
        log_message("INFO", "Simulated fingerprint match detected via UART");
        return 1;  // Match confirmed
    }
    
    return 0;  // No match or no data
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

    // Initialize random number generator
    srand((unsigned int)time(NULL));

    log_message("INFO", "Starting secure MAVLink sender with standard protocol...");

    if (init_network() != 0) {
        log_message("ERROR", "Network initialization failed");
        return 1;
    }

    if (crypto_init(&crypto_ctx, password) != 0) {
        log_message("ERROR", "Crypto initialization failed");
        cleanup_network();
        return 1;
    }

    atexit(cleanup_sender);

    if (init_udp_sender(server_ip) != 0) {
        return 1;
    }

    log_message("INFO", "Secure MAVLink sender initialized successfully");

    int cycle = 0;
    int fingerprint_sent = 0;

                //  int fingerprint_sent = 0;
    
 while (1) {
        
        if (!fingerprint_sent) {
            int fingerprint_match = read_fingerprint_uart();
            if (fingerprint_match) {
                if (send_fingerprint_confirmation(1, 1) == 0) {
                    fingerprint_sent = 1;
                    log_message("CRITICAL", "Fingerprint confirmation sent - ESP32 job done!");
                    break; // Exit after sending approval
                }
            }
        }
        
        Sleep(1000); // Check fingerprint every second
    }
    
    log_message("INFO", "ESP32 authentication complete. Shutting down.");
    return 0;
}
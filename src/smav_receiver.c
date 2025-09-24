#include "common.h"
#include "crypto_utils.h"

#ifdef _WIN32
    #include <windows.h>
#else
    #include <signal.h>
#endif

#define BUFFER_SIZE 1024
#define MAX_PAYLOAD_LEN 255

static crypto_context_t crypto_ctx;
static int udp_socket = -1;
static volatile int running = 1;
static int fc_initialized = 0;  // Flight controller initialization flag

// Replay protection
static uint32_t last_sequence = 0;
static uint32_t last_timestamp = 0;

// Outer MAVLink message structure for parsing encrypted tunnel
typedef struct {
    uint8_t sys_id;
    uint8_t comp_id;
    uint32_t msg_id;
    uint8_t payload[MAX_PAYLOAD_LEN];
    uint8_t payload_len;
} outer_mavlink_message_t;

uint16_t mavlink_crc_calculate(const uint8_t *buffer, size_t length) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < length; i++) {
        uint8_t tmp = buffer[i] ^ (uint8_t)(crc & 0xFF);
        tmp ^= (tmp << 4);
        crc = (crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4);
    }
    return crc;
}

// Parse outer MAVLink v2 packet (encrypted tunnel)
int parse_outer_mavlink(const uint8_t *buffer, size_t len, outer_mavlink_message_t *msg) {
    if (len < 12 || buffer[0] != 0xFD) {
        return -1; // Invalid magic or too short
    }

    uint8_t payload_len = buffer[1];
    uint8_t incompat_flags = buffer[2];
    uint8_t compat_flags = buffer[3];
    uint8_t seq = buffer[4];
    uint8_t sys_id = buffer[5];
    uint8_t comp_id = buffer[6];
    uint32_t msg_id = buffer[7] | (buffer[8] << 8) | (buffer[9] << 16);

    if (len < 12 + payload_len) {
        return -1; // Incomplete packet
    }

    // Calculate CRC
    uint16_t crc_calc = mavlink_crc_calculate(&buffer[1], 9 + payload_len);
    uint8_t crc_extra = 0; // For custom encrypted tunnel message
    uint16_t tmp_crc = crc_calc;
    uint8_t low = crc_extra ^ (tmp_crc & 0xff);
    low ^= (low << 4);
    tmp_crc = (tmp_crc >> 8) ^ (low << 8) ^ (low << 3) ^ (low >> 4);
    crc_calc = tmp_crc;

    uint16_t crc_received = buffer[10 + payload_len] | (buffer[11 + payload_len] << 8);

    if (crc_calc != crc_received) {
        log_message("ERROR", "Outer MAVLink CRC mismatch: calc=0x%04X received=0x%04X", 
                   crc_calc, crc_received);
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

// Process standard MAVLink GPS_RAW_INT message
void process_gps_raw_int(const mavlink_gps_raw_int_t* gps) {
    if (!fc_initialized) {
        log_message("WARNING", "GPS data received but FC not initialized");
        return;
    }
    
    log_message("INFO", "GPS Data - Lat: %.6f, Lon: %.6f, Alt: %.1fm, Sats: %d, Fix: %d",
                gps->lat / 1e7, gps->lon / 1e7, gps->alt / 1000.0f, 
                gps->satellites_visible, gps->fix_type);
}

// Process standard MAVLink ATTITUDE message
void process_attitude(const mavlink_attitude_t* att) {
    if (!fc_initialized) {
        log_message("WARNING", "IMU data received but FC not initialized");
        return;
    }
    
    log_message("INFO", "IMU Data - Roll: %.2f, Pitch: %.2f, Yaw: %.2f deg",
                att->roll * 180.0f / 3.14159f, 
                att->pitch * 180.0f / 3.14159f, 
                att->yaw * 180.0f / 3.14159f);
}

// Process standard MAVLink HEARTBEAT message
void process_heartbeat(const mavlink_heartbeat_t* hb) {
    if (!fc_initialized) {
        log_message("WARNING", "Heartbeat received but FC not initialized");
        return;
    }
    
    log_message("INFO", "Heartbeat - Type: %u, Autopilot: %u, Mode: %u, State: %u",
                hb->type, hb->autopilot, hb->base_mode, hb->system_status);
}

// Process fingerprint confirmation command
void process_fingerprint_command(const mavlink_command_long_t* cmd) {
    if (cmd->command != MAV_CMD_FINGERPRINT_CONFIRM) {
        return;
    }
    
    uint8_t match_confirmed = (uint8_t)cmd->param1;
    uint8_t system_id = (uint8_t)cmd->param2;
    uint32_t timestamp = (uint32_t)cmd->param3;
    
    log_message("INFO", "Fingerprint confirmation received - System: %u, Match: %u, Time: %u",
                system_id, match_confirmed, timestamp);
    
    if (match_confirmed == 1 && !fc_initialized) {
        fc_initialized = 1;
        log_message("CRITICAL", "*** FLIGHT CONTROLLER INITIALIZED ***");
        log_message("CRITICAL", "*** FINGERPRINT AUTHENTICATION SUCCESSFUL ***");
        log_message("CRITICAL", "*** DRONE OPERATIONS ENABLED ***");
        
        // TODO: Add actual FC initialization code here
        // For PX4: px4_fc_initialize();
        // For ArduPilot: ardupilot_fc_initialize();
        // Enable motors, sensors, navigation, etc.
        
    } else if (match_confirmed == 0) {
        log_message("ERROR", "Fingerprint authentication failed - FC remains locked");
    }
}

// Process decrypted standard MAVLink message
int process_decrypted_mavlink(const uint8_t* mavlink_data, size_t data_len) {
    mavlink_message_t msg;
    mavlink_status_t status;
    
    // Parse the decrypted standard MAVLink packet
    int parsed = 0;
    for (size_t i = 0; i < data_len; i++) {
        if (mavlink_parse_char(MAVLINK_COMM_0, mavlink_data[i], &msg, &status)) {
            parsed = 1;
            break;
        }
    }
    
    if (!parsed) {
        log_message("ERROR", "Failed to parse decrypted MAVLink data");
        print_hex("Invalid MAVLink data: ", mavlink_data, data_len);
        return -1;
    }

    log_message("DEBUG", "Decrypted standard MAVLink message ID: %u", msg.msgid);

    // Process based on standard MAVLink message ID
    switch (msg.msgid) {
        case MAVLINK_MSG_ID_GPS_RAW_INT: {
            mavlink_gps_raw_int_t gps;
            mavlink_msg_gps_raw_int_decode(&msg, &gps);
            process_gps_raw_int(&gps);
            break;
        }
        
        case MAVLINK_MSG_ID_ATTITUDE: {
            mavlink_attitude_t att;
            mavlink_msg_attitude_decode(&msg, &att);
            process_attitude(&att);
            break;
        }
        
        case MAVLINK_MSG_ID_HEARTBEAT: {
            mavlink_heartbeat_t hb;
            mavlink_msg_heartbeat_decode(&msg, &hb);
            process_heartbeat(&hb);
            break;
        }
        
        case MAVLINK_MSG_ID_COMMAND_LONG: {
            mavlink_command_long_t cmd;
            mavlink_msg_command_long_decode(&msg, &cmd);
            process_fingerprint_command(&cmd);
            break;
        }
        
        default:
            log_message("WARNING", "Unknown standard MAVLink message ID: %u", msg.msgid);
            break;
    }

    return 0;
}

// Process secure message wrapper
int process_secure_message(crypto_context_t* ctx, const secure_mavlink_t* secure_msg) {
    // Replay protection
    uint32_t current_time = get_timestamp();
    if (secure_msg->sequence_number <= last_sequence) {
        log_message("ERROR", "Replay attack detected - sequence number: %u <= %u", 
                   secure_msg->sequence_number, last_sequence);
        return -1;
    }
    
    if (abs((int32_t)(secure_msg->timestamp - current_time)) > 30) {  // 30s window
        log_message("ERROR", "Message timestamp out of range: %u vs %u", 
                   secure_msg->timestamp, current_time);
        return -2;
    }
    
    last_sequence = secure_msg->sequence_number;
    last_timestamp = secure_msg->timestamp;

    // Decrypt the inner standard MAVLink packet
    uint8_t decrypted_data[MAX_DATA_SIZE];
    size_t decrypted_len;

    int ret = decrypt_message(ctx, (const secure_message_t*)secure_msg, 
                             decrypted_data, &decrypted_len);
    if (ret != 0) {
        log_message("ERROR", "Message decryption failed: %d", ret);
        return ret;
    }

    // Verify decrypted length matches expected inner length
    if (decrypted_len != secure_msg->inner_length) {
        log_message("ERROR", "Decrypted length mismatch: %zu != %u", 
                   decrypted_len, secure_msg->inner_length);
        return -3;
    }

    log_message("DEBUG", "Successfully decrypted %zu bytes of standard MAVLink data", decrypted_len);
    print_hex("Decrypted MAVLink: ", decrypted_data, decrypted_len);

    // Process the decrypted standard MAVLink message
    return process_decrypted_mavlink(decrypted_data, decrypted_len);
}

int main(int argc, char* argv[]) {
    const char* password = "drone_secure_2024";

    if (argc > 1) {
        password = argv[1];
    }

    log_message("INFO", "Starting secure MAVLink receiver with standard protocol support...");

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
    log_message("INFO", "*** FLIGHT CONTROLLER LOCKED - Waiting for fingerprint confirmation ***");

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

        // Parse outer MAVLink packet (encrypted tunnel)
        outer_mavlink_message_t outer_msg;
        if (parse_outer_mavlink(buffer, (size_t)received, &outer_msg) != 0) {
            log_message("WARNING", "Invalid outer MAVLink packet received (%zd bytes)", received);
            continue;
        }

        // Only process encrypted tunnel messages (msg_id = 250)
        if (outer_msg.msg_id != 250) {
            log_message("DEBUG", "Non-encrypted MAVLink message ID %u ignored", outer_msg.msg_id);
            continue;
        }

        log_message("DEBUG", "Received encrypted tunnel message (%u bytes payload)", outer_msg.payload_len);

        // Reconstruct secure_mavlink_t from outer payload
        secure_mavlink_t secure_msg = {0};
        const uint8_t* ptr = outer_msg.payload;

        if (outer_msg.payload_len < (4+4+4+2+1+1+AES_IV_SIZE+HMAC_SIZE)) {
            log_message("ERROR", "Payload too small for secure message: %u bytes", outer_msg.payload_len);
            continue;
        }

        secure_msg.message_id = *(uint32_t*)ptr; ptr += 4;
        secure_msg.timestamp = *(uint32_t*)ptr; ptr += 4;
        secure_msg.sequence_number = *(uint32_t*)ptr; ptr += 4;
        secure_msg.inner_length = *(uint16_t*)ptr; ptr += 2;
        secure_msg.message_type = *ptr; ptr += 1;
        secure_msg.reserved = *ptr; ptr += 1;
        memcpy(secure_msg.iv, ptr, AES_IV_SIZE); ptr += AES_IV_SIZE;

        // Calculate padded length for encrypted data
        size_t padded_len = ((secure_msg.inner_length + 15) / 16) * 16;
        size_t expected_total = 4+4+4+2+1+1+AES_IV_SIZE + padded_len + HMAC_SIZE;
        
        if (outer_msg.payload_len != expected_total) {
            log_message("ERROR", "Invalid payload length: %u (expected %zu)", 
                       outer_msg.payload_len, expected_total);
            continue;
        }

        memcpy(secure_msg.encrypted_data, ptr, padded_len); ptr += padded_len;
        memcpy(secure_msg.hmac, ptr, HMAC_SIZE);

        // Process the secure message
        int result = process_secure_message(&crypto_ctx, &secure_msg);
        if (result != 0) {
            log_message("ERROR", "Failed to process secure message: %d", result);
        }
    }

    log_message("INFO", "Receiver shutting down...");
    return 0;
}
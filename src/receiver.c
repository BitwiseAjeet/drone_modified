// ==================== receiver.c ====================
#include "common.h"
#include "crypto_utils.h"

#ifdef _WIN32
    #include <windows.h>
    #include <process.h>
#else
    #include <signal.h>
    #include <pthread.h>
#endif

#define AES_IV_SIZE 16
#define MAX_DATA_SIZE 512
#define SERVER_PORT 8888
#define HMAC_SIZE 32

static crypto_context_t crypto_ctx;
static int server_socket = -1;
static volatile int running = 1;

typedef struct {
    int client_socket;
    struct sockaddr_in client_addr;
    crypto_context_t* crypto_ctx;
} client_connection_t;

void cleanup_receiver(void) {
    running = 0;
    if (server_socket >= 0) {
        close(server_socket);
    }
    crypto_cleanup(&crypto_ctx);
    cleanup_network();
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
void handle_signal(int sig) {
    log_message("INFO", "Received signal %d, shutting down...", sig);
    cleanup_receiver();
    exit(0);
}
// Drone sensor data structures
/*typedef struct {
    double latitude;
    double longitude;
    double altitude;
    float speed;
    uint8_t satellites;
} gps_data_t;*/

void process_gps_data(const gps_data_t* gps) {
    log_message("INFO", "GPS Data - Lat: %.6f, Lon: %.6f, Alt: %.1fm, Speed: %.1fkm/h, Sats: %d",
                gps->latitude, gps->longitude, gps->altitude, gps->speed, gps->satellites);
}

/*typedef struct {
    float accel_x, accel_y, accel_z;
    float gyro_x, gyro_y, gyro_z;
    float mag_x, mag_y, mag_z;
    uint32_t timestamp;
} imu_data_t;*/
void process_imu_data(const imu_data_t* imu) {
    log_message("INFO", "IMU Data - Accel(%.2f,%.2f,%.2f) Gyro(%.1f,%.1f,%.1f) Mag(%.1f,%.1f,%.1f)",
                imu->accel_x, imu->accel_y, imu->accel_z,
                imu->gyro_x, imu->gyro_y, imu->gyro_z,
                imu->mag_x, imu->mag_y, imu->mag_z);
}

void process_heartbeat(const uint32_t* timestamp) {
    log_message("INFO", "Heartbeat received - Timestamp: %u", *timestamp);
}



/*typedef struct {
    uint32_t message_id;
    uint32_t timestamp;
    uint32_t sequence_number;
    uint16_t data_length;
    uint8_t message_type;
    uint8_t reserved;
    uint8_t iv[AES_IV_SIZE];
    uint8_t encrypted_data[MAX_DATA_SIZE];
    uint8_t hmac[HMAC_SIZE];
} __attribute__((packed)) secure_message_t;*/

int process_secure_message(crypto_context_t* ctx, const secure_message_t* secure_msg) {
    uint8_t decrypted_data[MAX_DATA_SIZE];
    size_t decrypted_len; 

    // Decrypt message
    int ret = crypto_decrypt(ctx, secure_msg->encrypted_data,    // ciphertext pointer
                           secure_msg->data_length,  decrypted_data, &decrypted_len);
    if (ret != 0) {
        log_message("ERROR", "Message decryption failed");
        return ret;
    }
    
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

    // Process based on message type
    switch (secure_msg->message_type) {
        case MSG_GPS_DATA:
            if (decrypted_len == sizeof(gps_data_t)) {
                process_gps_data((const gps_data_t*)decrypted_data);
            } else {
                log_message("ERROR", "Invalid GPS data size: %d", (int)decrypted_len);
            }
            break;
            
        case MSG_IMU_DATA:
            if (decrypted_len == sizeof(imu_data_t)) {
                process_imu_data((const imu_data_t*)decrypted_data);
            } else {
                log_message("ERROR", "Invalid IMU data size: %d", (int)decrypted_len);
            }
            break;
            
        case MSG_HEARTBEAT:
            if (decrypted_len == sizeof(uint32_t)) {
                process_heartbeat((const uint32_t*)decrypted_data);
            } else {
                log_message("ERROR", "Invalid heartbeat data size: %d", (int)decrypted_len);
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
            log_message("WARNING", "Unknown message type: %d", secure_msg->message_type);
            break;
    }
    
    return 0;
}

#ifdef _WIN32
DWORD WINAPI handle_client(LPVOID param) {
#else
void* handle_client(void* param) {
#endif
    client_connection_t* conn = (client_connection_t*)param;
    secure_message_t secure_msg;
    char client_ip[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &conn->client_addr.sin_addr, client_ip, sizeof(client_ip));
    log_message("INFO", "Client connected from %s:%d", client_ip, ntohs(conn->client_addr.sin_port));
    
    while (running) {
        // Receive secure message
        int received = recv(conn->client_socket, (char*)&secure_msg, sizeof(secure_msg), 0);
        
        if (received == 0) {
            log_message("INFO", "Client %s disconnected", client_ip);
            break;
        } else if (received < 0) {
#ifdef _WIN32
            int error = WSAGetLastError();
            if (error != WSAEWOULDBLOCK) {
                log_message("ERROR", "Receive error from %s: %d", client_ip, error);
                break;
            }
#else
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                log_message("ERROR", "Receive error from %s: %s", client_ip, strerror(errno));
                break;
            }
#endif
            continue;
        } else if (received != sizeof(secure_msg)) {
            log_message("WARNING", "Partial message received from %s: %d bytes", client_ip, received);
            continue;
        }
        
        // Process the secure message
        if (process_secure_message(conn->crypto_ctx, &secure_msg) != 0) {
            log_message("ERROR", "Failed to process message from %s", client_ip);
        }
    }
    
    close(conn->client_socket);
    free(conn);
    
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

int start_server(void) {
    struct sockaddr_in server_addr;
    int opt = 1;
    
    // Create server socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        log_message("ERROR", "Server socket creation failed: %s", strerror(errno));
        return -1;
    }
    
    // Set socket options
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt)) < 0) {
        log_message("ERROR", "setsockopt failed: %s", strerror(errno));
        close(server_socket);
        return -1;
    }
    
    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SERVER_PORT);
    
    // Bind socket
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        log_message("ERROR", "Bind failed: %s", strerror(errno));
        close(server_socket);
        return -1;
    }
    
    // Listen for connections
    if (listen(server_socket, 5) < 0) {
        log_message("ERROR", "Listen failed: %s", strerror(errno));
        close(server_socket);
        return -1;
    }
    
    log_message("INFO", "Server listening on port %d", SERVER_PORT);
    
    return 0;
}

int main(int argc, char* argv[]) {
    const char* password = "drone_secure_2024";
    
    if (argc > 1) {
        password = argv[1];
    }
    
    log_message("INFO", "Starting secure drone receiver...");
    
    // Setup signal handlers
#ifndef _WIN32
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
#endif
    
    // Initialize network
    if (init_network() != 0) {
        log_message("ERROR", "Network initialization failed");
        return 1;
    }
    
    // Initialize crypto
    if (crypto_init(&crypto_ctx , "drone_secure_2024") != 0) {  // Remove password parameter
        log_message("ERROR", "Crypto initialization failed");
        cleanup_network();
        return 1;
    }
    
    // Setup cleanup handler
    atexit(cleanup_receiver);
    
    // Start server
    if (start_server() != 0) {
        return 1;
    }
    
    log_message("INFO", "Drone receiver initialized successfully");
    
    // Accept client connections
    while (running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket < 0) {
            if (running) {
                log_message("ERROR", "Accept failed: %s", strerror(errno));
            }
            continue;
        }
        
        // Create client connection structure
        client_connection_t* conn = malloc(sizeof(client_connection_t));
        if (!conn) {
            log_message("ERROR", "Failed to allocate memory for client connection");
            close(client_socket);
            continue;
        }
        
        conn->client_socket = client_socket;
        conn->client_addr = client_addr;
        conn->crypto_ctx = &crypto_ctx;
        
        // Handle client in separate thread
#ifdef _WIN32
        HANDLE thread = CreateThread(NULL, 0, handle_client, conn, 0, NULL);
        if (thread == NULL) {
            log_message("ERROR", "Failed to create client thread");
            close(client_socket);
            free(conn);
        } else {
            CloseHandle(thread); // Detach thread
        }
#else
        pthread_t thread;
        if (pthread_create(&thread, NULL, handle_client, conn) != 0) {
            log_message("ERROR", "Failed to create client thread");
            close(client_socket);
            free(conn);
        } else {
            pthread_detach(thread); // Detach thread
        }
#endif
    }
    
    return 0;
}
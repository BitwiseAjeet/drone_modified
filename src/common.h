#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #define close closesocket
#else
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <unistd.h>
#endif

#define DEFAULT_PORT 8080
#define BUFFER_SIZE 1024
#define MAX_MESSAGE_SIZE 512

typedef enum {
    MSG_HEARTBEAT = 1,
    MSG_STATUS = 2,
    MSG_COMMAND = 3,
    MSG_TELEMETRY = 4
} message_type_t;

typedef struct {
    message_type_t type;
    uint32_t timestamp;
    uint16_t sequence;
    uint16_t payload_size;
    uint8_t payload[MAX_MESSAGE_SIZE];
} drone_message_t;

int init_network(void);
void cleanup_network(void);
void print_message(const drone_message_t *msg);
uint32_t get_timestamp(void);

#endif

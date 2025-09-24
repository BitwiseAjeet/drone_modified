#include "common.h"
#include <stdarg.h>
#include <time.h>

int init_network(void) {
#ifdef _WIN32
WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (result != 0) {
        printf("WSAStartup failed: %d\n", result);
        return -1;
    }
#endif
    return 0;
}



void cleanup_network(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

void print_message(const drone_message_t *msg) {
    printf("Message Type: %d, Timestamp: %u, Sequence: %u, Size: %u\n",
           msg->type, msg->timestamp, msg->sequence, msg->payload_size);
}

uint32_t get_timestamp(void) {
    return (uint32_t)time(NULL);
}


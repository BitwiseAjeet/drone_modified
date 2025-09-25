# Makefile for Drone Security System - Windows/MinGW64
# Updated for encrypted standard MAVLink communication

CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -D_WIN32_WINNT=0x0601 -Isrc -Ilibs/mbedtls/include -Imavlink/generated_common
LDFLAGS = -lws2_32 -lbcrypt -ladvapi32

# Directories
SRCDIR = src
BINDIR = bin
MBEDTLS_SRC = libs/mbedtls/library

# Source files
COMMON_SRC = $(SRCDIR)/common.c $(SRCDIR)/crypto_utils.c

# Original TCP applications
SENDER_SRC = $(SRCDIR)/sender.c $(COMMON_SRC)
RECEIVER_SRC = $(SRCDIR)/receiver.c $(COMMON_SRC)

# Original MAVLink applications (custom protocol)
MAVLINK_SENDER_SRC = $(SRCDIR)/mavlink_sender.c $(COMMON_SRC)
MAVLINK_RECEIVER_SRC = $(SRCDIR)/mavlink_receiver.c $(COMMON_SRC)

# Legacy MAVLink applications
MAVLINK_SMAV_RECEIVER_SRC = $(SRCDIR)/smav_receiver.c $(COMMON_SRC)
MAVLINK_SMAV_SENDER_SRC = $(SRCDIR)/smav_sender.c $(COMMON_SRC)

# Use ALL available mbedTLS source files
MBEDTLS_SOURCES = $(wildcard $(MBEDTLS_SRC)/*.c)

# Target executables
SENDER_TARGET = $(BINDIR)/sender.exe
RECEIVER_TARGET = $(BINDIR)/receiver.exe
MAVLINK_SENDER_TARGET = $(BINDIR)/mavlink_sender.exe
MAVLINK_RECEIVER_TARGET = $(BINDIR)/mavlink_receiver.exe
SMAV_SENDER_TARGET = $(BINDIR)/smav_sender.exe
SMAV_RECEIVER_TARGET = $(BINDIR)/smav_receiver.exe

.PHONY: all clean sender receiver mavlink-sender mavlink-receiver smav-sender smav-receiver \
        tcp-apps mavlink-apps smav-apps test help check

# Build everything
all: $(BINDIR) $(SENDER_TARGET) $(RECEIVER_TARGET) $(MAVLINK_SENDER_TARGET) $(MAVLINK_RECEIVER_TARGET) $(SMAV_SENDER_TARGET) $(SMAV_RECEIVER_TARGET)
	@echo "Build completed successfully!"

$(BINDIR):
	@mkdir -p $(BINDIR)

# TCP applications (original)
$(SENDER_TARGET): $(SENDER_SRC) $(MBEDTLS_SOURCES) | $(BINDIR)
	@echo "Building TCP drone sender..."
	@echo "Using $(words $(MBEDTLS_SOURCES)) mbedTLS source files"
	$(CC) $(CFLAGS) -o $@ $(SENDER_SRC) $(MBEDTLS_SOURCES) $(LDFLAGS)
	@echo "TCP Sender built successfully"

$(RECEIVER_TARGET): $(RECEIVER_SRC) $(MBEDTLS_SOURCES) | $(BINDIR)
	@echo "Building TCP ground station receiver..."
	$(CC) $(CFLAGS) -o $@ $(RECEIVER_SRC) $(MBEDTLS_SOURCES) $(LDFLAGS)
	@echo "TCP Receiver built successfully"

# Standard MAVLink encrypted applications (new)
$(MAVLINK_SENDER_TARGET): $(MAVLINK_SENDER_SRC) $(MBEDTLS_SOURCES) | $(BINDIR)
	@echo "Building encrypted standard MAVLink sender (ESP32 prototype)..."
	$(CC) $(CFLAGS) -o $@ $(MAVLINK_SENDER_SRC) $(MBEDTLS_SOURCES) $(LDFLAGS)
	@echo "Encrypted MAVLink Sender built successfully"

$(MAVLINK_RECEIVER_TARGET): $(MAVLINK_RECEIVER_SRC) $(MBEDTLS_SOURCES) | $(BINDIR)
	@echo "Building encrypted standard MAVLink receiver (Flight Controller prototype)..."
	$(CC) $(CFLAGS) -o $@ $(MAVLINK_RECEIVER_SRC) $(MBEDTLS_SOURCES) $(LDFLAGS)
	@echo "Encrypted MAVLink Receiver built successfully"

# Legacy MAVLink applications (if they exist)
$(SMAV_SENDER_TARGET): $(MAVLINK_SMAV_SENDER_SRC) $(MBEDTLS_SOURCES) | $(BINDIR)
	@echo "Building legacy MAVLink sender..."
	$(CC) $(CFLAGS) -o $@ $(MAVLINK_SMAV_SENDER_SRC) $(MBEDTLS_SOURCES) $(LDFLAGS)
	@echo "Legacy MAVLink Sender built successfully"

$(SMAV_RECEIVER_TARGET): $(MAVLINK_SMAV_RECEIVER_SRC) $(MBEDTLS_SOURCES) | $(BINDIR)
	@echo "Building legacy MAVLink receiver..."
	$(CC) $(CFLAGS) -o $@ $(MAVLINK_SMAV_RECEIVER_SRC) $(MBEDTLS_SOURCES) $(LDFLAGS)
	@echo "Legacy MAVLink Receiver built successfully"

# Individual targets
sender: $(SENDER_TARGET)
receiver: $(RECEIVER_TARGET)
mavlink-sender: $(MAVLINK_SENDER_TARGET)
mavlink-receiver: $(MAVLINK_RECEIVER_TARGET)
smav-sender: $(SMAV_SENDER_TARGET)
smav-receiver: $(SMAV_RECEIVER_TARGET)

# Application groups
tcp-apps: sender receiver
	@echo "TCP applications built"

mavlink-apps: mavlink-sender mavlink-receiver
	@echo "Encrypted standard MAVLink applications built"

smav-apps: smav-sender smav-receiver
	@echo "Legacy MAVLink applications built"

# Check dependencies and project structure
check:
	@echo "Checking project dependencies..."
	@echo "Compiler:"
	@which $(CC) || echo "  ERROR: GCC not found"
	@echo "Project structure:"
	@echo "  Source directory:"
	@ls -la $(SRCDIR)/ 2>/dev/null || echo "  ERROR: src/ directory not found"
	@echo "  MAVLink headers:"
	@ls mavlink/generated_common/mavlink.h >/dev/null 2>&1 && echo "  OK: MAVLink headers found" || echo "  ERROR: MAVLink headers missing"
	@echo "  mbedTLS library:"
	@echo "    Found $(words $(MBEDTLS_SOURCES)) source files in $(MBEDTLS_SRC)/"
	@echo "Required source files for encrypted MAVLink:"
	@for file in common.c crypto_utils.c mavlink_sender.c mavlink_receiver.c; do \
		if [ -f "$(SRCDIR)/$$file" ]; then echo "  OK: $$file"; else echo "  MISSING: $$file"; fi; \
	done

# Test targets
test-tcp: tcp-apps
	@echo "Testing TCP applications..."
	@echo "Start receiver in one terminal: ./$(RECEIVER_TARGET)"
	@echo "Start sender in another terminal: ./$(SENDER_TARGET)"

test-mavlink: mavlink-apps
	@echo "Testing encrypted MAVLink applications..."
	@echo "Start receiver in one terminal: ./$(MAVLINK_RECEIVER_TARGET)"
	@echo "Start sender in another terminal: ./$(MAVLINK_SENDER_TARGET)"
	@echo "The sender will simulate fingerprint confirmation and send encrypted telemetry"

test-encrypted-demo: mavlink-apps
	@echo "Running encrypted MAVLink demo..."
	@echo "Starting receiver in background..."
	@start /B $(MAVLINK_RECEIVER_TARGET)
	@timeout /T 2 /NOBREAK >NUL
	@echo "Starting sender..."
	@$(MAVLINK_SENDER_TARGET)

clean:
	@echo "Cleaning up..."
	@rm -rf $(BINDIR)
	@echo "Clean completed"

help:
	@echo "Drone Security System - Build Options:"
	@echo ""
	@echo "BUILD TARGETS:"
	@echo "  all              - Build everything (TCP + encrypted MAVLink + legacy)"
	@echo "  tcp-apps         - Build TCP sender and receiver only"
	@echo "  mavlink-apps     - Build encrypted standard MAVLink apps only"
	@echo "  smav-apps        - Build legacy MAVLink apps (if present)"
	@echo ""
	@echo "INDIVIDUAL TARGETS:"
	@echo "  sender           - Build TCP sender only"
	@echo "  receiver         - Build TCP receiver only"
	@echo "  mavlink-sender   - Build encrypted MAVLink sender (ESP32 prototype)"
	@echo "  mavlink-receiver - Build encrypted MAVLink receiver (FC prototype)"
	@echo "  smav-sender      - Build legacy MAVLink sender"
	@echo "  smav-receiver    - Build legacy MAVLink receiver"
	@echo ""
	@echo "UTILITIES:"
	@echo "  check            - Check dependencies and project structure"
	@echo "  test-tcp         - Show TCP testing instructions"
	@echo "  test-mavlink     - Show encrypted MAVLink testing instructions"
	@echo "  clean            - Clean all build files"
	@echo "  help             - Show this help"
	@echo ""
	@echo "ENCRYPTED MAVLINK SYSTEM:"
	@echo "  The mavlink-sender encrypts standard MAVLink packets (GPS, IMU, etc.)"
	@echo "  and sends them via UDP. The mavlink-receiver decrypts and processes them."
	@echo "  This maintains full MAVLink compatibility while adding security."
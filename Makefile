# Makefile for Drone Security System - Windows/MinGW64
# Updated for MAVLink extension while keeping TCP originals

CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -D_WIN32_WINNT=0x0601 -Isrc -Ilibs/mbedtls/include
LDFLAGS = -lws2_32 -lbcrypt -ladvapi32
CFLAGS = -Wall -Wextra -std=c99 -Isrc -Imavlink -Imavlink/common

# Directories
SRCDIR = src
BINDIR = bin
MBEDTLS_SRC = libs/mbedtls/library

# Source files
COMMON_SRC = $(SRCDIR)/common.c $(SRCDIR)/crypto_utils.c
SENDER_SRC = $(SRCDIR)/sender.c $(COMMON_SRC)
RECEIVER_SRC = $(SRCDIR)/receiver.c $(COMMON_SRC)
MAVLINK_SENDER_SRC = $(SRCDIR)/mavlink_sender.c $(COMMON_SRC)
MAVLINK_RECEIVER_SRC = $(SRCDIR)/mavlink_receiver.c $(COMMON_SRC)

# Use ALL available mbedTLS source files (only ones that exist)
MBEDTLS_SOURCES = $(wildcard $(MBEDTLS_SRC)/*.c)

# Targets
SENDER_TARGET = $(BINDIR)/sender.exe
RECEIVER_TARGET = $(BINDIR)/receiver.exe
MAVLINK_SENDER_TARGET = $(BINDIR)/mavlink_sender.exe
MAVLINK_RECEIVER_TARGET = $(BINDIR)/mavlink_receiver.exe

.PHONY: all clean sender receiver mavlink-sender mavlink-receiver mavlink-apps test help

all: $(BINDIR) $(SENDER_TARGET) $(RECEIVER_TARGET) $(MAVLINK_SENDER_TARGET) $(MAVLINK_RECEIVER_TARGET)
	@echo "✅ Build completed successfully!"

$(BINDIR):
	@mkdir -p $(BINDIR)

$(SENDER_TARGET): $(SENDER_SRC) $(MBEDTLS_SOURCES) | $(BINDIR)
	@echo "🚁 Building TCP drone sender..."
	@echo "Using $(words $(MBEDTLS_SOURCES)) mbedTLS source files"
	$(CC) $(CFLAGS) -o $@ $(SENDER_SRC) $(MBEDTLS_SOURCES) $(LDFLAGS)
	@echo "✓ TCP Sender built successfully"

$(RECEIVER_TARGET): $(RECEIVER_SRC) $(MBEDTLS_SOURCES) | $(BINDIR)
	@echo "🛰️  Building TCP ground station receiver..."
	$(CC) $(CFLAGS) -o $@ $(RECEIVER_SRC) $(MBEDTLS_SOURCES) $(LDFLAGS)
	@echo "✓ TCP Receiver built successfully"

$(MAVLINK_SENDER_TARGET): $(MAVLINK_SENDER_SRC) $(MBEDTLS_SOURCES) | $(BINDIR)
	@echo "🚀 Building MAVLink drone sender..."
	$(CC) $(CFLAGS) -o $@ $(MAVLINK_SENDER_SRC) $(MBEDTLS_SOURCES) $(LDFLAGS)
	@echo "✓ MAVLink Sender built successfully"

$(MAVLINK_RECEIVER_TARGET): $(MAVLINK_RECEIVER_SRC) $(MBEDTLS_SOURCES) | $(BINDIR)
	@echo "📡 Building MAVLink ground station receiver..."
	$(CC) $(CFLAGS) -o $@ $(MAVLINK_RECEIVER_SRC) $(MBEDTLS_SOURCES) $(LDFLAGS)
	@echo "✓ MAVLink Receiver built successfully"

sender: $(SENDER_TARGET)

receiver: $(RECEIVER_TARGET)

mavlink-sender: $(MAVLINK_SENDER_TARGET)

mavlink-receiver: $(MAVLINK_RECEIVER_TARGET)

mavlink-apps: mavlink-sender mavlink-receiver

clean:
	@echo "🧹 Cleaning up..."
	@rm -rf $(BINDIR)
	@echo "✓ Clean completed"

test: all
	@echo "🧪 Running tests..."
	@echo "Test functionality not implemented yet"

help:
	@echo "Available targets:"
	@echo "  all              - Build everything (TCP + MAVLink)"
	@echo "  sender           - Build TCP sender only"
	@echo "  receiver         - Build TCP receiver only"
	@echo "  mavlink-sender   - Build MAVLink sender only"
	@echo "  mavlink-receiver - Build MAVLink receiver only"
	@echo "  mavlink-apps     - Build MAVLink sender and receiver"
	@echo "  clean            - Clean all build files"
	@echo "  test             - Run tests"
	@echo "  help             - Show this help"
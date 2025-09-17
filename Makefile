# Makefile for Drone Security System - Windows/MinGW64
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -D_WIN32_WINNT=0x0601 -Isrc -Ilibs/mbedtls/include
LDFLAGS = -lws2_32 -lbcrypt -ladvapi32

# Directories
SRCDIR = src
BINDIR = bin
MBEDTLS_SRC = libs/mbedtls/library

# Source files
COMMON_SRC = $(SRCDIR)/common.c $(SRCDIR)/crypto_utils.c
SENDER_SRC = $(SRCDIR)/sender.c $(COMMON_SRC)
RECEIVER_SRC = $(SRCDIR)/receiver.c $(COMMON_SRC)

# Use ALL available mbedTLS source files (only ones that exist)
MBEDTLS_SOURCES = $(wildcard $(MBEDTLS_SRC)/*.c)

# Targets
SENDER_TARGET = $(BINDIR)/sender.exe
RECEIVER_TARGET = $(BINDIR)/receiver.exe

.PHONY: all clean sender receiver test help

all: $(BINDIR) $(SENDER_TARGET) $(RECEIVER_TARGET)
	@echo "✅ Build completed successfully!"

$(BINDIR):
	@mkdir -p $(BINDIR)

$(SENDER_TARGET): $(SENDER_SRC) $(MBEDTLS_SOURCES) | $(BINDIR)
	@echo "🚁 Building drone sender..."
	@echo "Using $(words $(MBEDTLS_SOURCES)) mbedTLS source files"
	$(CC) $(CFLAGS) -o $@ $(SENDER_SRC) $(MBEDTLS_SOURCES) $(LDFLAGS)
	@echo "✓ Sender built successfully"

$(RECEIVER_TARGET): $(RECEIVER_SRC) $(MBEDTLS_SOURCES) | $(BINDIR)
	@echo "🛰️  Building ground station receiver..."
	$(CC) $(CFLAGS) -o $@ $(RECEIVER_SRC) $(MBEDTLS_SOURCES) $(LDFLAGS)
	@echo "✓ Receiver built successfully"

sender: $(SENDER_TARGET)

receiver: $(RECEIVER_TARGET)

clean:
	@echo "🧹 Cleaning up..."
	@rm -rf $(BINDIR)
	@echo "✓ Clean completed"

test: all
	@echo "🧪 Running tests..."
	@echo "Test functionality not implemented yet"

help:
	@echo "Available targets:"
	@echo "  all      - Build everything (default)"
	@echo "  sender   - Build sender only"
	@echo "  receiver - Build receiver only"  
	@echo "  clean    - Clean all build files"
	@echo "  test     - Run tests"
	@echo "  help     - Show this help"
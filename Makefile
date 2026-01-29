# Makefile for MDMPatcher-Linux
# Build tool for removing MDM profiles from iOS devices

CC = gcc
CFLAGS = -Wall -Wextra -D_GNU_SOURCE -I.
LDFLAGS = -lreadline -lm -lsqlite3

# Package config for external libraries
PKG_CONFIG = pkg-config
PKG_LIBS = libimobiledevice-1.0 libimobiledevice-glue-1.0 libplist-2.0 openssl libzip libirecovery-1.0

# Get flags from pkg-config
PKG_CFLAGS := $(shell $(PKG_CONFIG) --cflags $(PKG_LIBS) 2>/dev/null)
PKG_LDFLAGS := $(shell $(PKG_CONFIG) --libs $(PKG_LIBS) 2>/dev/null)

# Source files
SRCS = main.c patch_logic.c idevicebackup2.c libidevicefunctions.c utils.c
OBJS = $(SRCS:.c=.o)

# Output binary
TARGET = mdm_patch

# Default target
all: check-deps $(TARGET)

# Check for required dependencies
check-deps:
	@$(PKG_CONFIG) --exists $(PKG_LIBS) || { \
		echo "Error: Missing dependencies. Please install:"; \
		echo "  - libimobiledevice"; \
		echo "  - libplist"; \
		echo "  - openssl"; \
		echo "  - libzip"; \
		echo "  - libirecovery"; \
		echo "  - sqlite3"; \
		echo "  - readline"; \
		echo ""; \
		echo "On macOS: brew install libimobiledevice libplist openssl libzip libirecovery sqlite readline"; \
		echo "On Ubuntu/Debian: apt install libimobiledevice-dev libplist-dev libssl-dev libzip-dev libirecovery-dev libsqlite3-dev libreadline-dev"; \
		exit 1; \
	}

# Link the binary
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(PKG_LDFLAGS) $(LDFLAGS)
	@echo ""
	@echo "Build successful: $(TARGET)"
	@echo "Run './$(TARGET) --help' for usage information"

# Compile source files
%.o: %.c
	$(CC) $(CFLAGS) $(PKG_CFLAGS) -c $< -o $@

# Debug build with symbols
debug: CFLAGS += -g -O0 -DDEBUG
debug: clean $(TARGET)
	@echo "Debug build complete"

# Release build with optimizations
release: CFLAGS += -O2 -DNDEBUG
release: clean $(TARGET)
	@echo "Release build complete"

# Clean build artifacts
clean:
	rm -f $(OBJS) $(TARGET)
	@echo "Cleaned build artifacts"

# Install to /usr/local/bin (requires sudo)
install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/
	@echo "Installed $(TARGET) to /usr/local/bin/"

# Uninstall from /usr/local/bin
uninstall:
	rm -f /usr/local/bin/$(TARGET)
	@echo "Uninstalled $(TARGET) from /usr/local/bin/"

# Show help
help:
	@echo "MDMPatcher-Linux Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build the binary (default)"
	@echo "  debug     - Build with debug symbols"
	@echo "  release   - Build with optimizations"
	@echo "  clean     - Remove build artifacts"
	@echo "  install   - Install to /usr/local/bin (requires sudo)"
	@echo "  uninstall - Remove from /usr/local/bin (requires sudo)"
	@echo "  help      - Show this help message"
	@echo ""
	@echo "Variables:"
	@echo "  CC        - C compiler (default: gcc)"
	@echo "  CFLAGS    - Additional compiler flags"
	@echo "  LDFLAGS   - Additional linker flags"

.PHONY: all check-deps debug release clean install uninstall help

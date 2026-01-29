# AGENTS.md - MDMPatcher-Linux

Guidelines for AI agents working on this codebase.

## Project Overview

MDMPatcher-Linux is a command-line tool for removing MDM profiles from iOS devices.
This is a Linux/Unix port of the original macOS GUI application, written in pure C.

- **Language**: C11 with GNU extensions (`-D_GNU_SOURCE`)
- **License**: Apache 2.0 (some files LGPL 2.1 from libimobiledevice)
- **Platform**: Linux, macOS (Unix-like systems)

## Build Commands

### Full Build

```bash
gcc -o mdm_patch \
    main.c \
    patch_logic.c \
    idevicebackup2.c \
    libidevicefunctions.c \
    utils.c \
    -I. \
    -D_GNU_SOURCE \
    $(pkg-config --cflags --libs libimobiledevice-1.0 libimobiledevice-glue-1.0 libplist-2.0 openssl libzip libirecovery-1.0) \
    -lreadline -lm -lsqlite3
```

### Debug Build (with symbols)

```bash
gcc -g -O0 -o mdm_patch \
    main.c patch_logic.c idevicebackup2.c libidevicefunctions.c utils.c \
    -I. -D_GNU_SOURCE \
    $(pkg-config --cflags --libs libimobiledevice-1.0 libimobiledevice-glue-1.0 libplist-2.0 openssl libzip libirecovery-1.0) \
    -lreadline -lm -lsqlite3
```

### Verify Dependencies

```bash
pkg-config --modversion libimobiledevice-1.0 libplist-2.0 openssl libzip libirecovery-1.0
```

## Testing

**No test framework is currently implemented.** Testing is manual via physical iOS devices.

### Template Mode Testing
```bash
./mdm_patch
```

### User Backup Mode Testing
```bash
# First decrypt a backup
python3 tools/decrypt_backup.py /path/to/encrypted_backup -o /path/to/decrypted

# Test with dry-run first
./mdm_patch -b /path/to/decrypted --dry-run

# Test actual restore
./mdm_patch -b /path/to/decrypted --in-place
```

Required resource files (must be in working directory for template mode):
- `extension1.pdf` - Encrypted Info.plist template
- `extension2.pdf` - Encrypted Manifest.plist template  
- `libiMobileeDevice.dylib` - Encrypted backup structure archive

## Code Style Guidelines

### Formatting

- **Indentation**: 4 spaces (no tabs)
- **Line length**: ~100 characters soft limit
- **Braces**: K&R style (opening brace on same line)
- **Line endings**: Unix (LF)

```c
// Correct
if (condition) {
    do_something();
} else {
    do_other();
}

// Correct function definition
int process_data(const char *input, size_t len) {
    // ...
}
```

### Naming Conventions

| Element | Style | Example |
|---------|-------|---------|
| Functions | `snake_case` | `read_file_to_buffer`, `get_string_from_xml` |
| Variables | `snake_case` | `xml_info`, `temp_path`, `out_len` |
| Constants | `SCREAMING_SNAKE_CASE` | `TOOL_NAME`, `CODE_SUCCESS` |
| Macros | `SCREAMING_SNAKE_CASE` | `PRINT_VERBOSE`, `LOCK_ATTEMPTS` |
| Typedefs | `snake_case_t` | `swift_callbacks`, `plist_format_t` |
| Enums | `snake_case` for type, `UPPER_CASE` for values | `enum cmd_mode`, `CMD_BACKUP` |

### Include Order

Group includes in this order, separated by blank lines:

```c
// 1. Config header (if exists)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

// 2. Standard library headers
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 3. System headers
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

// 4. External library headers
#include <plist/plist.h>
#include <openssl/evp.h>
#include <libimobiledevice/libimobiledevice.h>

// 5. Local project headers
#include "utils.h"
#include "patch_logic.h"
```

### Error Handling

- Return `0` for success, non-zero (typically `-1` or `1`) for failure
- Use `fprintf(stderr, ...)` for error messages
- Use early returns to handle errors
- Always clean up resources (free memory, close files) before returning

```c
int process_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "Error: Could not open file %s\n", path);
        return -1;
    }
    
    char *buffer = malloc(1024);
    if (!buffer) {
        fclose(f);
        return -1;
    }
    
    // ... process ...
    
    free(buffer);
    fclose(f);
    return 0;
}
```

### Memory Management

- Use `malloc`/`free` for heap allocations
- Document ownership in function comments when returning allocated memory
- Free all allocated memory before function returns (no leaks)
- Check `malloc` return values for NULL

```c
/**
 * @brief Reads entire file into buffer.
 * @return Heap-allocated buffer. Caller must free().
 */
unsigned char* read_file_to_buffer(const char* filename, size_t* size);
```

### Documentation

- Use Doxygen-style comments for public function declarations in headers
- Use `//` for inline comments explaining logic
- Use `/* */` for file headers and license blocks

```c
/**
 * @brief Decrypts RNCryptor v3 formatted data.
 * @param input The encrypted input buffer
 * @param input_len Length of input buffer
 * @param password Decryption password
 * @param output Pointer to receive decrypted data (caller must free)
 * @param out_len Pointer to receive output length
 * @return 0 on success, -1 on failure
 */
int decrypt_data(unsigned char* input, size_t input_len, const char* password,
                 unsigned char** output, size_t* out_len);
```

## Architecture

```
mdmpatcher/
├── main.c                  # Entry point, device detection, workflow orchestration
├── patch_logic.c/.h        # RNCryptor decryption, plist patching, ZIP extraction
├── idevicebackup2.c/.h     # MobileBackup2 protocol (restore to device)
├── libidevicefunctions.c/.h # iOS device communication wrappers
├── utils.c/.h              # String utilities, file I/O, plist helpers
├── endianness.h            # Cross-platform byte order macros
├── extension1.pdf          # Encrypted Info.plist template (resource)
├── extension2.pdf          # Encrypted Manifest.plist template (resource)
├── libiMobileeDevice.dylib # Encrypted backup structure (resource)
└── tools/
    ├── decrypt_backup.py   # Python script to decrypt iOS encrypted backups
    ├── requirements.txt    # Python dependencies (iphone_backup_decrypt, tqdm)
    └── setup_venv.sh       # Helper script to set up Python virtual environment
```

### Module Responsibilities

| Module | Purpose |
|--------|---------|
| `main.c` | Program entry, device info retrieval, orchestrates patching workflow |
| `patch_logic` | Handles decryption (AES-256-CBC), byte swaps, plist generation, ConfigProfiles injection |
| `idevicebackup2` | Implements Apple's MobileBackup2 protocol for restore operations |
| `libidevicefunctions` | Wraps libimobiledevice for device queries (lockdownd) |
| `utils` | Path building, size formatting, plist file I/O |
| `tools/decrypt_backup.py` | Decrypts iOS encrypted backups preserving restore-compatible structure |

## Common Patterns

### Plist Handling

```c
plist_t plist = NULL;
plist_from_xml(xml_string, strlen(xml_string), &plist);
if (plist) {
    plist_t node = plist_dict_get_item(plist, "KeyName");
    if (node && plist_get_node_type(node) == PLIST_STRING) {
        char *value = NULL;
        plist_get_string_val(node, &value);
        // use value...
        free(value);
    }
    plist_free(plist);
}
```

### File Operations

```c
FILE *f = fopen(path, "rb");
if (!f) return NULL;

fseek(f, 0, SEEK_END);
size_t size = ftell(f);
fseek(f, 0, SEEK_SET);

unsigned char *buffer = malloc(size);
fread(buffer, 1, size, f);
fclose(f);
```

### String Replacement

Use the project's `str_replace()` function for template substitution:
```c
char *result = str_replace(original, "placeholder", "actual_value");
// caller must free(result)
```

## Important Notes

1. **No Makefile**: Build uses direct gcc invocation (see Build Commands above)
2. **Resource files required**: The encrypted `.pdf` and `.dylib` files must be present for template mode
3. **Device required**: Full testing requires a physical iOS device
4. **libimobiledevice stack**: Must be built from source in correct order (see README.md)
5. **Python tooling**: `tools/decrypt_backup.py` requires Python 3.8+ and dependencies from `tools/requirements.txt`

## Python Tooling

The `tools/` directory contains Python scripts for backup processing:

### Setup
```bash
cd tools
./setup_venv.sh        # Creates virtual environment and installs dependencies
source .venv/bin/activate
```

### Dependencies
- `iphone_backup_decrypt` - iOS backup decryption library
- `tqdm` - Progress bar for file processing

### Usage
```bash
python3 tools/decrypt_backup.py <encrypted_backup> -o <output_dir> [-p password]
```

# MDM Patcher (Linux/Unix Port)

<div align="center">

**Command-line tool for removing MDM profiles from iOS devices**

[Overview](#overview) • [Requirements](#requirements) • [Building](#building-from-source) • [Usage](#usage) • [Troubleshooting](#troubleshooting)

</div>

---

## ⚠️ Legal & Ethical Disclaimer

> **This tool is intended strictly for educational, diagnostic, and personal device recovery use only.**
>
> - Must **ONLY** be used on iOS devices that you **legally own** and have the right to modify
> - **Does NOT jailbreak, exploit, or modify iOS firmware**
> - Uses only public interfaces (AFC, plist editing, USB restore protocols)
> - Designed for scenarios like second-hand devices where MDM was not properly removed
>
> **Using this software on managed, corporate, or institutional devices without explicit permission is prohibited and may be illegal in your jurisdiction.**

---

## Overview

MDM Patcher is a command-line tool that helps remove Mobile Device Management (MDM) profiles from supervised iPhones and iPads. This is the Linux/Unix port of the original macOS GUI application.

**Key Features:**
- ✅ No jailbreak required
- ✅ No firmware modifications
- ✅ Works on Linux, macOS, and potentially other Unix systems
- ✅ Command-line interface for automation
- ✅ Supports iOS 15.0 - 18.5+
- ✅ Works with iPhone 5s through iPhone 16, all iPad models

---

## Requirements

### Hardware
- iOS device (iPhone 5s or newer, any iPad with Lightning/USB-C)
- USB cable
- Computer running Linux (Ubuntu/Debian recommended) or macOS

### Software Prerequisites
- GCC or Clang compiler
- pkg-config
- Git (for cloning dependencies)

### Required Dependencies
The following libraries must be installed:

| Library | Version | Purpose |
|---------|---------|---------|
| **libimobiledevice** | 1.3.0+ | iOS device communication |
| **libimobiledevice-glue** | 1.0.0+ | Supporting utilities for libimobiledevice |
| **libplist** | 2.2.0+ | Property list parsing |
| **libusbmuxd** | 2.0.0+ | USB multiplexing daemon |
| **OpenSSL** | 1.1.0+ or 3.0+ | Cryptographic operations (AES, HMAC) |
| **libzip** | 1.7.0+ | ZIP archive handling |
| **readline** | 8.0+ | Command-line input (optional) |
| **libirecovery** | 1.0.0+ | Recovery mode device communication |
| **SQLite3** | 3.0+ | Manifest.db database handling |

---

## Building from Source

### Ubuntu/Debian Installation

#### 1. Install System Dependencies

```bash
sudo apt update
sudo apt install -y \
    build-essential \
    pkg-config \
    git \
    autoconf \
    automake \
    libtool \
    libssl-dev \
    libzip-dev \
    libreadline-dev \
    libusb-1.0-0-dev \
    usbmuxd
```

#### 2. Build libimobiledevice Stack

The libimobiledevice ecosystem must be built in order. Follow these steps:

```bash
# Create a build directory
mkdir -p ~/mdm-build && cd ~/mdm-build

# 1. libplist
git clone https://github.com/libimobiledevice/libplist.git
cd libplist
./autogen.sh
make
sudo make install
cd ..

# 2. libimobiledevice-glue
git clone https://github.com/libimobiledevice/libimobiledevice-glue.git
cd libimobiledevice-glue
./autogen.sh
make
sudo make install
cd ..

# 3. libusbmuxd
git clone https://github.com/libimobiledevice/libusbmuxd.git
cd libusbmuxd
./autogen.sh
make
sudo make install
cd ..

# 4. libimobiledevice
git clone https://github.com/libimobiledevice/libimobiledevice.git
cd libimobiledevice
./autogen.sh
make
sudo make install
cd ..

# Update library cache
sudo ldconfig
```

#### 3. Verify Installation

```bash
# Check if libraries are found
pkg-config --modversion libimobiledevice-1.0
pkg-config --modversion libplist-2.0
pkg-config --modversion libirecovery-1.0
pkg-config --libs openssl libzip

# Test device detection
idevice_id -l
```

If `idevice_id -l` shows your device UDID, the installation is successful.

#### 4. Prepare Required Files

Place these files in your working directory:
- `extension1.pdf` - Info.plist template (encrypted)
- `extension2.pdf` - Manifest.plist template (encrypted)
- `libiMobileeDevice.dylib` - Backup structure archive (encrypted)

**Note:** These files are not included in this repository. They must be obtained from the original MDMPatcher Enhanced macOS application bundle.

#### 5. Compile MDM Patcher

```bash
# Clone or download the source code
git clone <your-repo-url>
cd mdmpatcher

# Compile
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

# Make executable
chmod +x mdm_patch
```

---


## Decrypting Encrypted Backups

If you have an encrypted iOS backup and want to use it with `--backup-source`, you must first decrypt it using the included Python tool.

### Setup

```bash
# Navigate to the tools directory
cd tools

# Option 1: Use the setup script (creates virtual environment)
./setup_venv.sh
source .venv/bin/activate

# Option 2: Install dependencies directly
pip install iphone_backup_decrypt tqdm
```

### Usage

```bash
# With password prompt (recommended)
python3 tools/decrypt_backup.py /path/to/encrypted_backup -o /path/to/decrypted_output

# With inline password
python3 tools/decrypt_backup.py /path/to/encrypted_backup -o /path/to/decrypted_output -p "your_password"
```

The decrypted backup will be created at the output path, preserving the iOS backup structure required for restoration.

**Note:** The decryption tool preserves the `BackupKeyBag` in `Manifest.plist`, which is required by iOS 15+ for restore operations.

---


## Usage

### Prerequisites

1. **Restore your device to factory settings** using iTunes/Finder or `idevicerestore`
2. **Do NOT complete the setup wizard** - stop at the WiFi selection screen
3. **Do NOT connect to WiFi** - this prevents MDM re-enrollment
4. Connect device via USB
5. Trust the computer when prompted on device

### Running the Patcher (Template Mode)

This mode uses the built-in template backup. It's the simplest approach but creates a minimal backup.

```bash
# Ensure required files are in the current directory
ls extension1.pdf extension2.pdf libiMobileeDevice.dylib

# Run the patcher
./mdm_patch
```

### Running the Patcher (User Backup Mode)

This mode uses your own decrypted backup, preserving your data while removing MDM profiles. This is useful when you want to keep apps, settings, and data from an existing backup.

```bash
# Step 1: Decrypt your encrypted backup (if needed)
python3 tools/decrypt_backup.py ~/Library/Application\ Support/MobileSync/Backup/DEVICE_UDID \
    -o ~/DecryptedBackup

# Step 2: Run the patcher with your backup
./mdm_patch --backup-source ~/DecryptedBackup

# Alternative: Modify backup in-place (saves disk space, modifies original)
./mdm_patch --backup-source ~/DecryptedBackup --in-place

# Alternative: Preview changes without restoring (dry-run)
./mdm_patch --backup-source ~/DecryptedBackup --dry-run

# Alternative: Specify target device UDID explicitly
./mdm_patch --backup-source ~/DecryptedBackup --target-udid 00008150-XXXX
```

**Command-line Options:**

| Option | Description |
|--------|-------------|
| `-b, --backup-source PATH` | Use existing decrypted backup instead of built-in template |
| `-u, --target-udid UDID` | Target device UDID (default: auto-detect connected device) |
| `-i, --in-place` | Modify backup directly instead of copying (saves disk space) |
| `-n, --dry-run` | Preview changes without performing restore |
| `-h, --help` | Show help message |
| `-V, --version` | Show version information |

### Expected Output

```
MDM Patcher v1.1
================

Waiting for device...
Device detected:
  Model:    iPad7,5
  Serial:   F9FWCCXHJF8M
  iOS:      21H450
  UDID:     00008030-001854E42E06402E

Preparing backup files...
[Patch 3] Extracting backup structure...
[Patch 3] Extracting 154 files...
[Patch 3] Extraction complete
[Patch 1] Processing Info.plist template...
[Patch 1] Info.plist created successfully
[Patch 2] Processing Manifest.plist template...
[Patch 2] Manifest.plist created successfully

Starting restore process...
Please keep device connected and unlocked.

Started "com.apple.mobilebackup2" service on port 49558.
Negotiated Protocol Version 2.1
Reading Info.plist from backup.
Starting Restore...
The device should reboot now.
Restore Successful.

✓ MDM patch applied successfully!
  Your device should now reboot.
  Complete the setup assistant to finish.
```

### After Successful Patch

1. Device will automatically reboot
2. Complete the iOS setup wizard normally
3. You can now connect to WiFi
4. Device should no longer prompt for MDM enrollment

---

## Troubleshooting

### "Error: Could not connect to device"

**Causes:**
- Device not connected or not trusted
- usbmuxd not running
- Permission issues

**Solutions:**
```bash
# Check if device is detected
idevice_id -l

# Restart usbmuxd
sudo systemctl restart usbmuxd
# OR
sudo killall usbmuxd && sudo usbmuxd

# Check USB permissions (add user to plugdev group on Linux)
sudo usermod -aG plugdev $USER
# Log out and back in for changes to take effect
```

### "Error: Failed to decrypt extension files"

**Causes:**
- Missing or corrupted template files
- Wrong file versions

**Solution:**
- Ensure `extension1.pdf`, `extension2.pdf`, and `libiMobileeDevice.dylib` are from the correct MDMPatcher Enhanced version
- Verify file integrity (files should be encrypted, not actual PDFs)

### "Restore Failed (Error Code: -1)"

**Causes:**
- Find My is still enabled
- Device not on Setup Assistant screen
- Device locked

**Solutions:**
1. Factory reset device again
2. Stop at WiFi selection (do NOT proceed further)
3. Ensure Find My iPhone is disabled (should be disabled after factory reset without WiFi)
4. Keep device unlocked during the process
5. Try rebooting device and starting over

### "Restore Failed (Error Code: -205)" / "No keybag in manifest"

**Causes:**
- Missing `BackupKeyBag` in `Manifest.plist` (required by iOS 15+)
- Backup was decrypted with an older version of the decrypt tool that removed the keybag

**Solutions:**
1. Re-decrypt your backup using the updated `tools/decrypt_backup.py` script
2. The updated script preserves `BackupKeyBag` which is required for iOS 15+ restore operations

```bash
# Re-decrypt with updated tool
python3 tools/decrypt_backup.py /path/to/original_encrypted_backup \
    -o /path/to/new_decrypted_backup
```

### Build Errors

**"Package libimobiledevice-1.0 was not found"**
```bash
# Rebuild library cache
sudo ldconfig

# Check PKG_CONFIG_PATH
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH

# Verify installation
pkg-config --list-all | grep libimobiledevice
```

**"undefined reference to PKCS5_PBKDF2_HMAC_SHA1"**
```bash
# Ensure OpenSSL is properly linked
pkg-config --libs openssl
# Should show: -lssl -lcrypto

# On macOS, you may need to explicitly link OpenSSL
# Add to compile command:
-I/opt/homebrew/opt/openssl/include -L/opt/homebrew/opt/openssl/lib
```

---

## Architecture Overview

### File Structure

```
mdmpatcher/
├── main.c                      # Entry point, device detection, workflow
├── patch_logic.c               # Decryption, patching, file generation
├── patch_logic.h               # Patch function declarations
├── idevicebackup2.c            # MobileBackup2 protocol implementation
├── idevicebackup2.h            # Backup restoration declarations
├── libidevicefunctions.c       # Device communication wrappers
├── libidevicefunctions.h       # Device function declarations
├── utils.c                     # Utility functions
├── utils.h                     # Utility declarations
├── endianness.h                # Endian conversion macros
├── extension1.pdf              # Encrypted Info.plist template
├── extension2.pdf              # Encrypted Manifest.plist template
├── libiMobileeDevice.dylib     # Encrypted backup structure
└── tools/
    ├── decrypt_backup.py       # Backup decryption script (Python)
    ├── requirements.txt        # Python dependencies
    └── setup_venv.sh           # Virtual environment setup script
```


## Credits & Acknowledgments

- Original **MDMPatcher Enhanced** by [fled-dev](https://github.com/fled-dev)
- **libimobiledevice** team for iOS communication libraries
- **RNCryptor** specification for the encryption format
- Community contributors for testing and feedback

## TODO

* Remove SetupState key from HomeDomain/Library/Preferences/com.apple.purplebuddy.plist before restoring pre-existing backup
* Maybe clean HomeDomain/Library/Accounts/Accounts3.sqlite entries? (Not confirmed if necessary)

---

## License

This project is provided as-is for educational purposes. Users are responsible for ensuring compliance with all applicable laws and regulations in their jurisdiction.

**Use at your own risk. The authors are not responsible for any damage, data loss, or legal consequences resulting from the use of this tool.**

---

## Changelog

### v1.1.0 (User Backup Mode)
- ✅ User backup mode (`--backup-source`) - restore from your own decrypted backups
- ✅ In-place modification (`--in-place`) - modify backup directly, saves disk space
- ✅ Dry-run mode (`--dry-run`) - preview changes without performing restore
- ✅ Target device UDID (`--target-udid`) - specify device explicitly
- ✅ Backup decryption tool (`tools/decrypt_backup.py`) - decrypt iOS encrypted backups
- ✅ ConfigurationProfiles injection - automatically injects clean profiles from template
- ✅ iOS 15+ BackupKeyBag compatibility - preserves keybag required for restore
- ✅ SQLite3 Manifest.db support - proper handling of backup database
- ✅ Improved error messages with specific error codes

### v1.0.0 (Initial Linux Port)
- ✅ Ported from Swift/macOS to C/Linux
- ✅ Implemented RNCryptor v3 decryption
- ✅ Added HMAC verification for password validation
- ✅ Integrated MobileBackup2 protocol
- ✅ Command-line interface
- ✅ Automatic cleanup on success
- ✅ Enhanced error messages and troubleshooting

---

## FAQ

**Q: Is this a jailbreak?**  
A: No. This tool does not modify iOS firmware or exploit any vulnerabilities. It uses Apple's legitimate backup restoration mechanism.

**Q: Will this work on a device that's currently enrolled in MDM?**  
A: No. The device must first be factory reset and stopped at the Setup Assistant WiFi screen.

**Q: Do I need to disable Find My iPhone?**  
A: Find My should be automatically disabled after a factory reset without WiFi connection. If it's still enabled, the restore will fail.

**Q: Can I use this on a corporate/school device?**  
A: **Absolutely not.** This is strictly for personally-owned devices only. Using this on managed devices without authorization is illegal.

**Q: Does this work on activation-locked devices?**  
A: No. Activation Lock is a separate security feature and cannot be bypassed with this tool.

---

<div align="center">

**For support and updates, visit the [repository](https://github.com/pruiz/MDMPatcher-Linux)**

*Based on [MDMPatcher Enhanced](https://github.com/fled-dev/MDMPatcher-Enhanced) by fled-dev*

*Last Updated: January 2026*

</div>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <zip.h>
#include <sys/stat.h>
#include <errno.h>
#include <dirent.h>
#include <time.h>
#include <plist/plist.h>
#include <sqlite3.h>
#include "patch_logic.h"
#include "utils.h"

// --- Helper: Recursive Directory Creation ---
int mkdir_p(const char *path) {
    char temp[1024];
    char *p = NULL;
    size_t len;
    snprintf(temp, sizeof(temp), "%s", path);
    len = strlen(temp);
    if (temp[len - 1] == '/') temp[len - 1] = 0;
    for (p = temp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            if (mkdir(temp, 0755) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(temp, 0755) != 0 && errno != EEXIST) return -1;
    return 0;
}

void ensure_parent_dir_exists(const char* filepath) {
    char* parent = strdup(filepath);
    char* slash = strrchr(parent, '/');
    if (slash) {
        *slash = '\0';
        mkdir_p(parent);
    }
    free(parent);
}

// --- Helper: String replacement ---
char* str_replace(const char* orig, const char* rep, const char* with) {
    char* result;
    char* ins;
    char* tmp;
    int len_rep;
    int len_with;
    int len_front;
    int count;
    if (!orig || !rep) return NULL;
    len_rep = strlen(rep);
    if (len_rep == 0) return NULL;
    if (!with) with = "";
    len_with = strlen(with);
    ins = (char*)orig;
    for (count = 0; (tmp = strstr(ins, rep)); ++count) ins = tmp + len_rep;
    tmp = result = malloc(strlen(orig) + (len_with - len_rep) * count + 1);
    if (!result) return NULL;
    while (count--) {
        ins = strstr(orig, rep);
        len_front = ins - orig;
        tmp = strncpy(tmp, orig, len_front) + len_front;
        tmp = strcpy(tmp, with) + len_with;
        orig += len_front + len_rep;
    }
    strcpy(tmp, orig);
    return result;
}

void apply_byte_swaps(unsigned char* data, size_t len) {
    if (len < 346) return;
    unsigned char tmp;
    #define SWAP(a, b) tmp = data[a]; data[a] = data[b]; data[b] = tmp;
    SWAP(3, 5); SWAP(8, 17); SWAP(128, 345);
    SWAP(15, 65); SWAP(33, 133); SWAP(16, 64);
}

// --- Core Logic: RNCryptor v3 Decryption with HMAC Verification ---
int try_decrypt_with_hmac(unsigned char* input, size_t input_len, const char* password, 
                          unsigned char** output, size_t* out_len) {
    if (input_len < 66) return -1;
    if (input[0] != 3) return -1;
    
    unsigned char* enc_salt = input + 2;
    unsigned char* hmac_salt = input + 10;
    unsigned char* iv = input + 18;
    unsigned char* ciphertext = input + 34;
    size_t cipher_len = input_len - 66;
    unsigned char* stored_hmac = input + input_len - 32;
    
    // Derive keys using PBKDF2-HMAC-SHA1 with 10,000 iterations (RNCryptor v3 spec)
    unsigned char enc_key[32];
    unsigned char hmac_key[32];
    
    PKCS5_PBKDF2_HMAC_SHA1(password, strlen(password), enc_salt, 8, 10000, 32, enc_key);
    PKCS5_PBKDF2_HMAC_SHA1(password, strlen(password), hmac_salt, 8, 10000, 32, hmac_key);
    
    // Verify HMAC (password check)
    unsigned char computed_hmac[32];
    unsigned int hmac_len;
    HMAC(EVP_sha256(), hmac_key, 32, input, input_len - 32, computed_hmac, &hmac_len);
    
    if (memcmp(computed_hmac, stored_hmac, 32) != 0) {
        return -1; // Wrong password
    }
    
    // Decrypt using AES-256-CBC
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, enc_key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    *output = malloc(cipher_len + 32);
    int len, final_len;
    
    if (EVP_DecryptUpdate(ctx, *output, &len, ciphertext, (int)cipher_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(*output);
        *output = NULL;
        return -1;
    }
    
    if (EVP_DecryptFinal_ex(ctx, *output + len, &final_len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        free(*output);
        *output = NULL;
        return -1;
    }
    
    *out_len = len + final_len;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

// Master decryption function using the correct password
int smart_decrypt(unsigned char* input, size_t len, unsigned char** output, size_t* out_len) {
    // Password derived from Swift's Double calculation and string interpolation
    // This exact byte sequence is required for decryption
    unsigned char password_bytes[] = {
        0x72, 0x65, 0x70, 0x6B, 0x77, 0x6F, 0x74, 0x6B, 0x67, 0x70, 0x65, 0x72, 0x67, 0x70, 0x65, 0x6F,
        0x6B, 0x72, 0x67, 0x6F, 0x6B, 0x67, 0x72, 0x6F, 0x65, 0x2D, 0x34, 0x2E, 0x30, 0x34, 0x31, 0x38,
        0x33, 0x36, 0x34, 0x32, 0x34, 0x38, 0x35, 0x34, 0x36, 0x39, 0x36, 0x35, 0x65, 0x2B, 0x32, 0x36,
        0x66, 0x64, 0x6C, 0x67, 0x6B, 0x64, 0x6C, 0x67, 0x66, 0x6B, 0x6C, 0x73, 0x64, 0xC3, 0xB6, 0x66,
        0x64, 0x67, 0x73, 0x6A, 0x2D, 0x34, 0x2E, 0x30, 0x34, 0x31, 0x38, 0x33, 0x36, 0x34, 0x32, 0x34,
        0x38, 0x35, 0x34, 0x36, 0x39, 0x36, 0x35, 0x65, 0x2B, 0x32, 0x36, 0x67, 0x66, 0x64, 0x61, 0x64,
        0x73, 0x32, 0x33, 0x6A, 0x69, 0x34, 0x6A, 0x67, 0x69, 0x33, 0x76, 0x72, 0x65, 0x77, 0xC3, 0xB6,
        0x00
    };
    
    return try_decrypt_with_hmac(input, len, (char*)password_bytes, output, out_len);
}

// --- Patch Functions ---

void patchFile1(const char* build, const char* imei, const char* type, const char* sn, const char* udid, const char* path) {
    printf("[Patch 1] Processing Info.plist template...\n");
    FILE* f = fopen("extension1.pdf", "rb");
    if (!f) {
        printf("[ERROR] extension1.pdf not found\n");
        return;
    }
    
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char* buffer = malloc(size);
    fread(buffer, 1, size, f);
    fclose(f);

    apply_byte_swaps(buffer, size);

    unsigned char* decrypted = NULL;
    size_t dec_len = 0;

    if (smart_decrypt(buffer, size, &decrypted, &dec_len) == 0) {
        apply_byte_swaps(decrypted, dec_len);

        char* str = malloc(dec_len + 1);
        memcpy(str, decrypted, dec_len);
        str[dec_len] = '\0';

        // Apply device-specific replacements
        char* working = str_replace(str, "18C66", build);
        
        char* next;
        if (strlen(imei) == 0) {
            char imei_block[100] = "\t<key>IMEI</key>\n\t<string>357145413514797</string>\n";
            next = str_replace(working, imei_block, "");
        } else {
            next = str_replace(working, "357145413514797", imei);
        }
        free(working);
        working = next;

        char* s3 = str_replace(working, "iPhone12,8", type);
        free(working);
        char* s4 = str_replace(s3, "F17F4MLSPLK2", sn);
        free(s3);
        char* final_str = str_replace(s4, "00008030-001854E42E06402E", udid);
        free(s4);

        char out_path[1024];
        sprintf(out_path, "%s/MDMB/Info.plist", path);
        ensure_parent_dir_exists(out_path);
        
        FILE* out_f = fopen(out_path, "wb");
        if (out_f) {
            fwrite(final_str, 1, strlen(final_str), out_f);
            fclose(out_f);
            printf("[Patch 1] Info.plist created successfully\n");
        } else {
            printf("[ERROR] Failed to write Info.plist: %s\n", strerror(errno));
        }
        
        free(final_str);
        free(str);
        free(decrypted);
    } else {
        printf("[ERROR] Failed to decrypt extension1.pdf\n");
    }
    free(buffer);
}

void patchFile2(const char* build, const char* imei, const char* type, const char* sn, const char* udid, const char* path) {
    printf("[Patch 2] Processing Manifest.plist template...\n");
    FILE* f = fopen("extension2.pdf", "rb");
    if (!f) {
        printf("[ERROR] extension2.pdf not found\n");
        return;
    }
    
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char* buffer = malloc(size);
    fread(buffer, 1, size, f);
    fclose(f);

    apply_byte_swaps(buffer, size);

    unsigned char* decrypted = NULL;
    size_t dec_len = 0;

    if (smart_decrypt(buffer, size, &decrypted, &dec_len) == 0) {
        apply_byte_swaps(decrypted, dec_len);

        char* str = malloc(dec_len + 1);
        memcpy(str, decrypted, dec_len);
        str[dec_len] = '\0';

        // Apply device-specific replacements
        char* s1 = str_replace(str, "18C66", build);
        char* s2 = str_replace(s1, "iPhone12,8", type);
        free(s1);
        char* s3 = str_replace(s2, "F17F4MLSPLK2", sn);
        free(s2);
        char* final_str = str_replace(s3, "00008030-001854E42E06402E", udid);
        free(s3);

        char out_path[1024];
        sprintf(out_path, "%s/MDMB/Manifest.plist", path);
        ensure_parent_dir_exists(out_path);

        FILE* out_f = fopen(out_path, "wb");
        if (out_f) {
            fwrite(final_str, 1, strlen(final_str), out_f);
            fclose(out_f);
            printf("[Patch 2] Manifest.plist created successfully\n");
        } else {
            printf("[ERROR] Failed to write Manifest.plist: %s\n", strerror(errno));
        }
        
        free(final_str);
        free(str);
        free(decrypted);
    } else {
        printf("[ERROR] Failed to decrypt extension2.pdf\n");
    }
    free(buffer);
}

void patchFile3(const char* zip_buffer, size_t len, const char* target_path) {
    printf("[Patch 3] Extracting backup structure...\n");
    unsigned char* data_copy = malloc(len);
    memcpy(data_copy, zip_buffer, len);
    apply_byte_swaps(data_copy, len);

    unsigned char* decrypted = NULL;
    size_t dec_len = 0;

    if (smart_decrypt(data_copy, len, &decrypted, &dec_len) == 0) {
        apply_byte_swaps(decrypted, dec_len);
        
        zip_error_t zerr;
        zip_source_t *src = zip_source_buffer_create(decrypted, dec_len, 0, &zerr);
        zip_t *za = zip_open_from_source(src, ZIP_RDONLY, &zerr);
        
        if (za) {
            zip_int64_t num_entries = zip_get_num_entries(za, 0);
            printf("[Patch 3] Extracting %lld files...\n", (long long)num_entries);
            
            for (zip_int64_t i = 0; i < num_entries; i++) {
                const char* name = zip_get_name(za, i, 0);
                char full_path[1024];
                sprintf(full_path, "%s/%s", target_path, name);
                ensure_parent_dir_exists(full_path);

                if (name[strlen(name)-1] == '/') {
                    mkdir_p(full_path);
                    continue;
                }

                zip_file_t *zf = zip_fopen_index(za, i, 0);
                if (zf) {
                    FILE* out = fopen(full_path, "wb");
                    if (out) {
                        char buf[8192];
                        zip_int64_t n;
                        while ((n = zip_fread(zf, buf, sizeof(buf))) > 0) {
                            fwrite(buf, 1, n, out);
                        }
                        fclose(out);
                    }
                    zip_fclose(zf);
                }
            }
            zip_close(za);
            printf("[Patch 3] Extraction complete\n");
        } else {
            printf("[ERROR] Failed to open ZIP archive\n");
        }
        free(decrypted);
    } else {
        printf("[ERROR] Failed to decrypt backup structure\n");
    }
    free(data_copy);
}

/* ========== User Backup Functions ========== */

/**
 * @brief Recursively copy a directory
 */
static int copy_directory_recursive(const char *src_path, const char *dst_path) {
    struct stat st;
    if (stat(src_path, &st) != 0) {
        return -1;
    }

    if (S_ISDIR(st.st_mode)) {
        // Create destination directory
        if (mkdir(dst_path, st.st_mode) != 0 && errno != EEXIST) {
            fprintf(stderr, "Error: Failed to create directory %s: %s\n", dst_path, strerror(errno));
            return -1;
        }

        DIR *dir = opendir(src_path);
        if (!dir) {
            fprintf(stderr, "Error: Failed to open directory %s: %s\n", src_path, strerror(errno));
            return -1;
        }

        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            // Skip . and ..
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }

            char src_file[2048], dst_file[2048];
            snprintf(src_file, sizeof(src_file), "%s/%s", src_path, entry->d_name);
            snprintf(dst_file, sizeof(dst_file), "%s/%s", dst_path, entry->d_name);

            if (copy_directory_recursive(src_file, dst_file) != 0) {
                closedir(dir);
                return -1;
            }
        }
        closedir(dir);
    } else if (S_ISREG(st.st_mode)) {
        // Copy regular file
        FILE *src = fopen(src_path, "rb");
        if (!src) {
            fprintf(stderr, "Error: Failed to open source file %s: %s\n", src_path, strerror(errno));
            return -1;
        }

        FILE *dst = fopen(dst_path, "wb");
        if (!dst) {
            fprintf(stderr, "Error: Failed to create destination file %s: %s\n", dst_path, strerror(errno));
            fclose(src);
            return -1;
        }

        char buffer[65536];
        size_t bytes;
        while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0) {
            if (fwrite(buffer, 1, bytes, dst) != bytes) {
                fprintf(stderr, "Error: Failed to write to %s\n", dst_path);
                fclose(src);
                fclose(dst);
                return -1;
            }
        }

        fclose(src);
        fclose(dst);
        chmod(dst_path, st.st_mode);
    }
    // Skip symlinks, special files, etc.

    return 0;
}

int validate_user_backup(const char *backup_path) {
    struct stat st;
    char path[1024];
    
    // Check directory exists
    if (stat(backup_path, &st) != 0) {
        fprintf(stderr, "Error: Backup path '%s' does not exist\n", backup_path);
        return -1;
    }
    if (!S_ISDIR(st.st_mode)) {
        fprintf(stderr, "Error: Backup path '%s' is not a directory\n", backup_path);
        return -1;
    }
    
    // Check Info.plist
    snprintf(path, sizeof(path), "%s/Info.plist", backup_path);
    if (stat(path, &st) != 0) {
        fprintf(stderr, "Error: Info.plist not found in backup\n");
        fprintf(stderr, "  Expected: %s\n", path);
        return -1;
    }
    
    // Check Manifest.plist
    snprintf(path, sizeof(path), "%s/Manifest.plist", backup_path);
    if (stat(path, &st) != 0) {
        fprintf(stderr, "Error: Manifest.plist not found in backup\n");
        fprintf(stderr, "  Expected: %s\n", path);
        return -1;
    }
    
    // Check encryption status
    plist_t manifest = NULL;
    if (plist_read_from_filename(&manifest, path)) {
        plist_t encrypted = plist_dict_get_item(manifest, "IsEncrypted");
        uint8_t is_encrypted = 0;
        if (encrypted && plist_get_node_type(encrypted) == PLIST_BOOLEAN) {
            plist_get_bool_val(encrypted, &is_encrypted);
        }
        plist_free(manifest);
        
        if (is_encrypted) {
            fprintf(stderr, "Error: Backup is encrypted.\n");
            fprintf(stderr, "\nPlease decrypt the backup first. Options:\n");
            fprintf(stderr, "  1. Use idevicebackup2: idevicebackup2 unback <backup_dir>\n");
            fprintf(stderr, "  2. Create a new unencrypted backup via iTunes/Finder\n");
            fprintf(stderr, "  3. Use a third-party tool like iMazing\n");
            return -1;
        }
    } else {
        fprintf(stderr, "Warning: Could not parse Manifest.plist, proceeding anyway\n");
    }
    
    printf("[Validate] Backup validation passed\n");
    return 0;
}

int copy_user_backup(const char *source_path, const char *target_path) {
    char mdmb_path[1024];
    snprintf(mdmb_path, sizeof(mdmb_path), "%s/MDMB", target_path);
    
    printf("[Copy] Copying backup to %s...\n", mdmb_path);
    
    // Count files first for progress indication
    struct stat st;
    DIR *dir = opendir(source_path);
    if (!dir) {
        fprintf(stderr, "Error: Cannot open source backup: %s\n", strerror(errno));
        return -1;
    }
    
    int file_count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            file_count++;
        }
    }
    closedir(dir);
    
    printf("[Copy] Copying %d items...\n", file_count);
    
    // Create MDMB directory
    if (mkdir(mdmb_path, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "Error: Failed to create %s: %s\n", mdmb_path, strerror(errno));
        return -1;
    }
    
    // Copy recursively
    if (copy_directory_recursive(source_path, mdmb_path) != 0) {
        fprintf(stderr, "Error: Failed to copy backup\n");
        return -1;
    }
    
    printf("[Copy] Backup copied successfully\n");
    return 0;
}

int patch_user_info_plist(const char *backup_path, 
                          const char *build_version,
                          const char *product_version,
                          const char *product_type, 
                          const char *serial_number, 
                          const char *udid, 
                          const char *imei,
                          int dry_run) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/Info.plist", backup_path);
    
    plist_t plist = NULL;
    if (!plist_read_from_filename(&plist, path)) {
        fprintf(stderr, "Error: Failed to read Info.plist from %s\n", path);
        return -1;
    }
    
    printf("[Info.plist] Updating fields:\n");
    
    // Helper macro for updating and printing changes
    #define UPDATE_STRING_FIELD(plist, key, value) do { \
        plist_t _old = plist_dict_get_item(plist, key); \
        char *_old_val = NULL; \
        if (_old && plist_get_node_type(_old) == PLIST_STRING) { \
            plist_get_string_val(_old, &_old_val); \
        } \
        printf("  %-20s: %s -> %s\n", key, _old_val ? _old_val : "(none)", value); \
        if (_old_val) free(_old_val); \
        plist_dict_set_item(plist, key, plist_new_string(value)); \
    } while(0)
    
    UPDATE_STRING_FIELD(plist, "Build Version", build_version);
    UPDATE_STRING_FIELD(plist, "Product Type", product_type);
    UPDATE_STRING_FIELD(plist, "Product Version", product_version);
    UPDATE_STRING_FIELD(plist, "Serial Number", serial_number);
    UPDATE_STRING_FIELD(plist, "Unique Identifier", udid);
    UPDATE_STRING_FIELD(plist, "Target Identifier", udid);
    
    // Handle IMEI
    if (imei && strlen(imei) > 0) {
        UPDATE_STRING_FIELD(plist, "IMEI", imei);
    } else {
        plist_t imei_node = plist_dict_get_item(plist, "IMEI");
        if (imei_node) {
            printf("  %-20s: (removing - WiFi-only device)\n", "IMEI");
            plist_dict_remove_item(plist, "IMEI");
        }
    }
    
    // Update Last Backup Date to current time
    time_t now = time(NULL);
    plist_dict_set_item(plist, "Last Backup Date", plist_new_unix_date((int64_t)now));
    printf("  %-20s: (updated to current time)\n", "Last Backup Date");
    
    #undef UPDATE_STRING_FIELD
    
    if (dry_run) {
        printf("[Info.plist] DRY RUN - no changes written\n");
    } else {
        // Detect original format and use same format
        // Info.plist is typically XML format
        if (plist_write_to_filename(plist, path, PLIST_FORMAT_XML)) {
            printf("[Info.plist] Updated successfully\n");
        } else {
            fprintf(stderr, "Error: Failed to write Info.plist\n");
            plist_free(plist);
            return -1;
        }
    }
    
    plist_free(plist);
    return 0;
}

int patch_user_manifest_plist(const char *backup_path,
                              const char *build_version,
                              const char *product_version,
                              const char *product_type,
                              const char *serial_number,
                              const char *udid,
                              int dry_run) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/Manifest.plist", backup_path);
    
    plist_t plist = NULL;
    if (!plist_read_from_filename(&plist, path)) {
        fprintf(stderr, "Error: Failed to read Manifest.plist from %s\n", path);
        return -1;
    }
    
    printf("[Manifest.plist] Updating fields:\n");
    
    // Get or create Lockdown dict
    plist_t lockdown = plist_dict_get_item(plist, "Lockdown");
    if (!lockdown) {
        printf("  Note: No Lockdown dict found, creating one\n");
        lockdown = plist_new_dict();
        plist_dict_set_item(plist, "Lockdown", lockdown);
    }
    
    // Helper macro
    #define UPDATE_LOCKDOWN_FIELD(key, value) do { \
        plist_t _old = plist_dict_get_item(lockdown, key); \
        char *_old_val = NULL; \
        if (_old && plist_get_node_type(_old) == PLIST_STRING) { \
            plist_get_string_val(_old, &_old_val); \
        } \
        printf("  Lockdown/%-15s: %s -> %s\n", key, _old_val ? _old_val : "(none)", value); \
        if (_old_val) free(_old_val); \
        plist_dict_set_item(lockdown, key, plist_new_string(value)); \
    } while(0)
    
    UPDATE_LOCKDOWN_FIELD("BuildVersion", build_version);
    UPDATE_LOCKDOWN_FIELD("ProductType", product_type);
    UPDATE_LOCKDOWN_FIELD("ProductVersion", product_version);
    UPDATE_LOCKDOWN_FIELD("SerialNumber", serial_number);
    UPDATE_LOCKDOWN_FIELD("UniqueDeviceID", udid);
    
    #undef UPDATE_LOCKDOWN_FIELD
    
    // Ensure IsEncrypted is false
    plist_t encrypted = plist_dict_get_item(plist, "IsEncrypted");
    if (encrypted) {
        uint8_t is_encrypted = 0;
        plist_get_bool_val(encrypted, &is_encrypted);
        if (is_encrypted) {
            printf("  IsEncrypted: true -> false\n");
            plist_dict_set_item(plist, "IsEncrypted", plist_new_bool(0));
        }
    }
    
    if (dry_run) {
        printf("[Manifest.plist] DRY RUN - no changes written\n");
    } else {
        // Manifest.plist is typically binary plist
        if (plist_write_to_filename(plist, path, PLIST_FORMAT_BINARY)) {
            printf("[Manifest.plist] Updated successfully\n");
        } else {
            fprintf(stderr, "Error: Failed to write Manifest.plist\n");
            plist_free(plist);
            return -1;
        }
    }
    
    plist_free(plist);
    return 0;
}

static int compute_file_sha1(const char *path, unsigned char *out_digest)
{
	FILE *f = fopen(path, "rb");
	if (!f) {
		return -1;
	}

	SHA_CTX ctx;
	unsigned char buf[32768];
	SHA1_Init(&ctx);
	while (1) {
		size_t r = fread(buf, 1, sizeof(buf), f);
		if (r > 0) {
			SHA1_Update(&ctx, buf, r);
		}
		if (r < sizeof(buf)) {
			break;
		}
	}
	SHA1_Final(out_digest, &ctx);
	fclose(f);
	return 0;
}

static void digest_to_hex(const unsigned char *digest, char *out_hex, size_t out_len)
{
	if (!digest || !out_hex || out_len < (SHA_DIGEST_LENGTH * 2 + 1)) {
		return;
	}
	for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
		snprintf(out_hex + (i * 2), 3, "%02x", digest[i]);
	}
	out_hex[SHA_DIGEST_LENGTH * 2] = '\0';
}

static int fix_manifest_db_sizes(sqlite3 *db, const char *backup_path, int dry_run,
                                 int show_size_mismatches) {
    sqlite3_stmt *stmt = NULL;
    sqlite3_stmt *update_stmt = NULL;
    int rc = 0;
    int updated = 0;
    int unchanged = 0;
    int missing = 0;
    int skipped = 0;

    rc = sqlite3_prepare_v2(db, "SELECT fileID, domain, relativePath, file FROM Files", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[Manifest.db] Error preparing size check: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    if (!dry_run) {
        rc = sqlite3_prepare_v2(db, "UPDATE Files SET file = ? WHERE fileID = ?", -1, &update_stmt, NULL);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "[Manifest.db] Error preparing size update: %s\n", sqlite3_errmsg(db));
            sqlite3_finalize(stmt);
            return -1;
        }
        sqlite3_exec(db, "BEGIN TRANSACTION", NULL, NULL, NULL);
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char *file_id = (const char *)sqlite3_column_text(stmt, 0);
        const char *domain = (const char *)sqlite3_column_text(stmt, 1);
        const char *relative_path = (const char *)sqlite3_column_text(stmt, 2);
        const unsigned char *file_blob = (const unsigned char *)sqlite3_column_blob(stmt, 3);
        int file_blob_len = sqlite3_column_bytes(stmt, 3);

        if (!file_id || strlen(file_id) < 2) {
            skipped++;
            continue;
        }

        char file_path[1024];
        snprintf(file_path, sizeof(file_path), "%s/%c%c/%s", backup_path, file_id[0], file_id[1], file_id);

        struct stat st;
        if (stat(file_path, &st) != 0) {
            missing++;
            continue;
        }

        if (!file_blob || file_blob_len <= 0) {
            skipped++;
            continue;
        }

        plist_t file_plist = NULL;
        plist_from_bin((const char *)file_blob, (uint32_t)file_blob_len, &file_plist);
        if (!file_plist) {
            skipped++;
            continue;
        }

        plist_t objects = plist_dict_get_item(file_plist, "$objects");
        plist_t mbfile = NULL;
        plist_t size_node = NULL;
        uint64_t manifest_size = 0;
        if (objects && plist_get_node_type(objects) == PLIST_ARRAY && plist_array_get_size(objects) > 1) {
            mbfile = plist_array_get_item(objects, 1);
        }
        if (mbfile && plist_get_node_type(mbfile) == PLIST_DICT) {
            size_node = plist_dict_get_item(mbfile, "Size");
        }
        if (size_node && plist_get_node_type(size_node) == PLIST_UINT) {
            plist_get_uint_val(size_node, &manifest_size);
        } else {
            plist_free(file_plist);
            skipped++;
            continue;
        }

        if ((uint64_t)st.st_size == manifest_size) {
            plist_free(file_plist);
            unchanged++;
            continue;
        }

        if (show_size_mismatches) {
            printf("[Manifest.db] Size mismatch: %s (%s/%s) %llu -> %llu\n",
                   file_id,
                   domain ? domain : "(unknown)",
                   relative_path ? relative_path : "(unknown)",
                   (unsigned long long)manifest_size,
                   (unsigned long long)st.st_size);
        }

        if (!dry_run) {
            plist_dict_set_item(mbfile, "Size", plist_new_uint((uint64_t)st.st_size));

            char *new_blob = NULL;
            uint32_t new_blob_len = 0;
            plist_to_bin(file_plist, &new_blob, &new_blob_len);
            if (new_blob && new_blob_len > 0) {
                sqlite3_bind_blob(update_stmt, 1, new_blob, new_blob_len, SQLITE_TRANSIENT);
                sqlite3_bind_text(update_stmt, 2, file_id, -1, SQLITE_TRANSIENT);
                if (sqlite3_step(update_stmt) == SQLITE_DONE) {
                    updated++;
                } else {
                    fprintf(stderr, "[Manifest.db] Failed to update size for %s\n", file_id);
                }
                sqlite3_reset(update_stmt);
                sqlite3_clear_bindings(update_stmt);
            } else {
                fprintf(stderr, "[Manifest.db] Failed to rebuild metadata for %s\n", file_id);
            }
            free(new_blob);
        }

        plist_free(file_plist);
        if (dry_run) {
            updated++;
        }
    }

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "[Manifest.db] Error reading Files table: %s\n", sqlite3_errmsg(db));
    }

    sqlite3_finalize(stmt);
    if (update_stmt) {
        sqlite3_finalize(update_stmt);
    }
    if (!dry_run) {
        sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
    }

    printf("[Manifest.db] Size check: %d updated, %d unchanged, %d missing, %d skipped\n",
           updated, unchanged, missing, skipped);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

static int fix_manifest_db_digests(sqlite3 *db, const char *backup_path, int dry_run,
                                   int show_digest_mismatches)
{
	sqlite3_stmt *stmt = NULL;
	sqlite3_stmt *update_stmt = NULL;
	int rc = 0;
	int updated = 0;
	int unchanged = 0;
	int missing = 0;
	int skipped = 0;
	int uid_entries = 0;
	int inline_entries = 0;

	rc = sqlite3_prepare_v2(db, "SELECT fileID, domain, relativePath, file FROM Files", -1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "[Manifest.db] Error preparing digest check: %s\n", sqlite3_errmsg(db));
		return -1;
	}

	if (!dry_run) {
		rc = sqlite3_prepare_v2(db, "UPDATE Files SET file = ? WHERE fileID = ?", -1, &update_stmt, NULL);
		if (rc != SQLITE_OK) {
			fprintf(stderr, "[Manifest.db] Error preparing digest update: %s\n", sqlite3_errmsg(db));
			sqlite3_finalize(stmt);
			return -1;
		}
		sqlite3_exec(db, "BEGIN TRANSACTION", NULL, NULL, NULL);
	}

	while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		const char *file_id = (const char *)sqlite3_column_text(stmt, 0);
		const char *domain = (const char *)sqlite3_column_text(stmt, 1);
		const char *relative_path = (const char *)sqlite3_column_text(stmt, 2);
		const unsigned char *file_blob = (const unsigned char *)sqlite3_column_blob(stmt, 3);
		int file_blob_len = sqlite3_column_bytes(stmt, 3);

		if (!file_id || strlen(file_id) < 2) {
			skipped++;
			continue;
		}

		char file_path[1024];
		snprintf(file_path, sizeof(file_path), "%s/%c%c/%s", backup_path, file_id[0], file_id[1], file_id);

		struct stat st;
		if (stat(file_path, &st) != 0) {
			missing++;
			continue;
		}

		if (!file_blob || file_blob_len <= 0) {
			skipped++;
			continue;
		}

		plist_t file_plist = NULL;
		plist_from_bin((const char *)file_blob, (uint32_t)file_blob_len, &file_plist);
		if (!file_plist) {
			skipped++;
			continue;
		}

		plist_t objects = plist_dict_get_item(file_plist, "$objects");
		plist_t mbfile = NULL;
		plist_t digest_node = NULL;
		plist_t digest_data_node = NULL;
		plist_t digest_container = NULL;
		uint64_t digest_uid = 0;
		int has_digest_uid = 0;
		int digest_container_is_dict = 0;
		if (objects && plist_get_node_type(objects) == PLIST_ARRAY && plist_array_get_size(objects) > 1) {
			mbfile = plist_array_get_item(objects, 1);
		}
		if (mbfile && plist_get_node_type(mbfile) == PLIST_DICT) {
			digest_node = plist_dict_get_item(mbfile, "Digest");
		}
		if (!digest_node) {
			plist_free(file_plist);
			skipped++;
			continue;
		}

		plist_type digest_type = plist_get_node_type(digest_node);
		if (digest_type == PLIST_UID) {
			plist_get_uid_val(digest_node, &digest_uid);
			has_digest_uid = 1;
			uid_entries++;
			if (!objects || plist_get_node_type(objects) != PLIST_ARRAY) {
				plist_free(file_plist);
				skipped++;
				continue;
			}
			if (digest_uid >= plist_array_get_size(objects)) {
				plist_free(file_plist);
				skipped++;
				continue;
			}
			digest_container = plist_array_get_item(objects, (uint32_t)digest_uid);
			digest_data_node = digest_container;
		} else if (digest_type == PLIST_DATA) {
			inline_entries++;
			digest_data_node = digest_node;
		}

		if (!digest_data_node) {
			plist_free(file_plist);
			skipped++;
			continue;
		}

		if (plist_get_node_type(digest_data_node) == PLIST_DICT) {
			plist_t nested = plist_dict_get_item(digest_data_node, "NS.data");
			if (nested && plist_get_node_type(nested) == PLIST_DATA) {
				digest_data_node = nested;
				digest_container_is_dict = 1;
			} else {
				plist_free(file_plist);
				skipped++;
				continue;
			}
		} else if (plist_get_node_type(digest_data_node) != PLIST_DATA) {
			plist_free(file_plist);
			skipped++;
			continue;
		}

		unsigned char digest[SHA_DIGEST_LENGTH];
		if (compute_file_sha1(file_path, digest) != 0) {
			plist_free(file_plist);
			skipped++;
			continue;
		}

		char *stored_data = NULL;
		uint64_t stored_len = 0;
		plist_get_data_val(digest_data_node, &stored_data, &stored_len);

		int is_match = 0;
		if (stored_data && stored_len == SHA_DIGEST_LENGTH) {
			if (memcmp(stored_data, digest, SHA_DIGEST_LENGTH) == 0) {
				is_match = 1;
			}
		}

		if (is_match) {
			free(stored_data);
			plist_free(file_plist);
			unchanged++;
			continue;
		}

		if (show_digest_mismatches) {
			char new_hex[SHA_DIGEST_LENGTH * 2 + 1];
			char old_hex[SHA_DIGEST_LENGTH * 2 + 1];
			digest_to_hex(digest, new_hex, sizeof(new_hex));
			if (stored_data && stored_len == SHA_DIGEST_LENGTH) {
				digest_to_hex((unsigned char *)stored_data, old_hex, sizeof(old_hex));
			} else {
				snprintf(old_hex, sizeof(old_hex), "%s", "(invalid)");
			}
			printf("[Manifest.db] Digest mismatch: %s (%s/%s) %s -> %s\n",
			       file_id,
			       domain ? domain : "(unknown)",
			       relative_path ? relative_path : "(unknown)",
			       old_hex,
			       new_hex);
		}

		if (has_digest_uid) {
			plist_t new_data = plist_new_data((const char *)digest, SHA_DIGEST_LENGTH);
			if (digest_container_is_dict && digest_container) {
				plist_dict_set_item(digest_container, "NS.data", new_data);
			} else {
				plist_array_set_item(objects, new_data, (uint32_t)digest_uid);
			}
		} else {
			plist_dict_set_item(mbfile, "Digest", plist_new_data((const char *)digest, SHA_DIGEST_LENGTH));
		}
		if (!dry_run) {
			char *new_blob = NULL;
			uint32_t new_blob_len = 0;
			plist_to_bin(file_plist, &new_blob, &new_blob_len);
			if (new_blob && new_blob_len > 0) {
				sqlite3_bind_blob(update_stmt, 1, new_blob, new_blob_len, SQLITE_TRANSIENT);
				sqlite3_bind_text(update_stmt, 2, file_id, -1, SQLITE_TRANSIENT);
				if (sqlite3_step(update_stmt) == SQLITE_DONE) {
					updated++;
				} else {
					fprintf(stderr, "[Manifest.db] Failed to update digest for %s\n", file_id);
				}
				sqlite3_reset(update_stmt);
				sqlite3_clear_bindings(update_stmt);
			} else {
				fprintf(stderr, "[Manifest.db] Failed to rebuild digest metadata for %s\n", file_id);
			}
			free(new_blob);
		} else {
			updated++;
		}

		free(stored_data);
		plist_free(file_plist);
	}

	if (rc != SQLITE_DONE) {
		fprintf(stderr, "[Manifest.db] Error reading digest data: %s\n", sqlite3_errmsg(db));
	}

	sqlite3_finalize(stmt);
	if (update_stmt) {
		sqlite3_finalize(update_stmt);
	}
	if (!dry_run) {
		sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
	}

	printf("[Manifest.db] Digest fix: %d updated, %d unchanged, %d missing, %d skipped\n",
	       updated, unchanged, missing, skipped);
	printf("[Manifest.db] Digest sources: %d uid, %d inline\n", uid_entries, inline_entries);

	return (rc == SQLITE_DONE) ? 0 : -1;
}

int patch_user_manifest_db(const char *backup_path,
                           const char *product_type,
                           const char *serial_number,
                           const char *udid,
                           int dry_run,
                           int ignore_manifest_sizes,
                           int show_size_mismatches,
                           int show_digest_mismatches) {
    char db_path[1024];
    snprintf(db_path, sizeof(db_path), "%s/Manifest.db", backup_path);
    
    struct stat st;
    if (stat(db_path, &st) != 0) {
        printf("[Manifest.db] Not found (older backup format) - skipping\n");
        return 0;  // Not an error for older backups
    }
    
    printf("[Manifest.db] Checking database...\n");
    
    if (dry_run) {
        printf("[Manifest.db] DRY RUN - would verify file structure\n");
        return 0;
    }
    
    sqlite3 *db = NULL;
    int rc = sqlite3_open(db_path, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Error: Cannot open Manifest.db: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    
    // Verify Files table exists and count entries
    sqlite3_stmt *stmt = NULL;
    rc = sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM Files", -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            int file_count = sqlite3_column_int(stmt, 0);
            printf("  Files table: %d entries (preserved - not modified)\n", file_count);
        }
        sqlite3_finalize(stmt);
    } else {
        printf("  Warning: Could not read Files table\n");
    }
    
    // Check for Properties table (some backups have this)
    rc = sqlite3_prepare_v2(db, "SELECT name FROM sqlite_master WHERE type='table' AND name='Properties'", -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            printf("  Properties table: found (device metadata stored here)\n");
            // Note: Properties table typically stores plist blobs, not individual fields
            // Modifying it safely requires careful plist parsing which is beyond scope
        }
        sqlite3_finalize(stmt);
    }
    
    if (!ignore_manifest_sizes) {
        if (fix_manifest_db_sizes(db, backup_path, dry_run, show_size_mismatches) != 0) {
            sqlite3_close(db);
            return -1;
        }
    } else {
        printf("[Manifest.db] Size fix-ups skipped (--ignore-manifest-sizes)\n");
    }

    if (fix_manifest_db_digests(db, backup_path, dry_run, show_digest_mismatches) != 0) {
        sqlite3_close(db);
        return -1;
    }

    sqlite3_close(db);
    printf("[Manifest.db] Verified successfully\n");
    return 0;
}

int update_status_plist(const char *backup_path, int dry_run) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/Status.plist", backup_path);
    
    struct stat st;
    plist_t plist = NULL;
    
    if (stat(path, &st) == 0) {
        // Status.plist exists, read it
        if (!plist_read_from_filename(&plist, path)) {
            printf("[Status.plist] Could not parse existing file, creating new\n");
            plist = NULL;
        }
    }
    
    if (!plist) {
        // Create new Status.plist
        printf("[Status.plist] Creating new Status.plist\n");
        plist = plist_new_dict();
    }
    
    printf("[Status.plist] Ensuring backup state is valid:\n");
    
    // Set required fields for a valid backup
    plist_t snapshot_state = plist_dict_get_item(plist, "SnapshotState");
    char *current_state = NULL;
    if (snapshot_state && plist_get_node_type(snapshot_state) == PLIST_STRING) {
        plist_get_string_val(snapshot_state, &current_state);
    }
    
    if (!current_state || strcmp(current_state, "finished") != 0) {
        printf("  SnapshotState: %s -> finished\n", current_state ? current_state : "(none)");
        plist_dict_set_item(plist, "SnapshotState", plist_new_string("finished"));
    } else {
        printf("  SnapshotState: finished (OK)\n");
    }
    if (current_state) free(current_state);
    
    // Ensure Version is set
    plist_t version = plist_dict_get_item(plist, "Version");
    if (!version) {
        printf("  Version: (none) -> 2.4\n");
        plist_dict_set_item(plist, "Version", plist_new_string("2.4"));
    }
    
    // Ensure IsFullBackup is set
    plist_t is_full = plist_dict_get_item(plist, "IsFullBackup");
    if (!is_full) {
        printf("  IsFullBackup: (none) -> true\n");
        plist_dict_set_item(plist, "IsFullBackup", plist_new_bool(1));
    }
    
    // Set BackupState to new
    plist_dict_set_item(plist, "BackupState", plist_new_string("new"));
    printf("  BackupState: new\n");
    
    if (dry_run) {
        printf("[Status.plist] DRY RUN - no changes written\n");
    } else {
        // Status.plist is typically binary plist
        if (plist_write_to_filename(plist, path, PLIST_FORMAT_BINARY)) {
            printf("[Status.plist] Updated successfully\n");
        } else {
            fprintf(stderr, "Error: Failed to write Status.plist\n");
            plist_free(plist);
            return -1;
        }
    }
    
    plist_free(plist);
    return 0;
}

/* ========== ConfigurationProfiles Injection ========== */

// MBDB entry structure
typedef struct {
    char *domain;
    char *filename;      // relativePath
    char file_id[41];    // computed SHA1 (40 hex chars + null)
    uint16_t mode;       // file mode (0x8000 = file, 0x4000 = dir)
    uint32_t uid;
    uint32_t gid;
    uint32_t mtime;
    uint64_t file_len;
    char *linktarget;
} mbdb_entry_t;

typedef struct {
    char *relative_path;
    char *file_id;
} existing_profile_t;

/**
 * @brief Compute SHA1 file ID from domain and relative path.
 * @param domain The backup domain (e.g., "HomeDomain")
 * @param relative_path The file path within domain
 * @param out_id Output buffer for 40-char hex string (must be at least 41 bytes)
 */
static void compute_file_id(const char *domain, const char *relative_path, char *out_id) {
    char input[2048];
    snprintf(input, sizeof(input), "%s-%s", domain, relative_path);
    
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1((unsigned char *)input, strlen(input), hash);
    
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf(out_id + (i * 2), "%02x", hash[i]);
    }
    out_id[40] = '\0';
}

/**
 * @brief Read a big-endian integer from buffer.
 */
static uint64_t read_be_int(const unsigned char *data, int size) {
    uint64_t value = 0;
    for (int i = 0; i < size; i++) {
        value = (value << 8) | data[i];
    }
    return value;
}

/**
 * @brief Read a length-prefixed string from MBDB buffer.
 * @return New offset after reading, or -1 on error
 */
static int read_mbdb_string(const unsigned char *data, size_t data_len, size_t offset, 
                            char **out_str) {
    if (offset + 2 > data_len) return -1;
    
    // Check for empty string marker (0xFFFF)
    if (data[offset] == 0xFF && data[offset + 1] == 0xFF) {
        *out_str = strdup("");
        return offset + 2;
    }
    
    uint16_t len = (data[offset] << 8) | data[offset + 1];
    offset += 2;
    
    if (offset + len > data_len) return -1;
    
    *out_str = malloc(len + 1);
    if (!*out_str) return -1;
    
    memcpy(*out_str, data + offset, len);
    (*out_str)[len] = '\0';
    
    return offset + len;
}

/**
 * @brief Parse Manifest.mbdb and extract ConfigurationProfiles entries.
 * @param mbdb_path Path to Manifest.mbdb file
 * @param entries Output array (caller must free with free_mbdb_entries)
 * @param count Output count of entries
 * @return 0 on success, -1 on failure
 */
static int parse_mbdb_for_config_profiles(const char *mbdb_path, 
                                           mbdb_entry_t **entries, 
                                           int *count) {
    FILE *f = fopen(mbdb_path, "rb");
    if (!f) {
        fprintf(stderr, "Error: Cannot open Manifest.mbdb: %s\n", strerror(errno));
        return -1;
    }
    
    fseek(f, 0, SEEK_END);
    size_t file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    unsigned char *data = malloc(file_size);
    if (!data) {
        fclose(f);
        fprintf(stderr, "Error: Failed to allocate memory for MBDB\n");
        return -1;
    }
    
    if (fread(data, 1, file_size, f) != file_size) {
        free(data);
        fclose(f);
        fprintf(stderr, "Error: Failed to read Manifest.mbdb\n");
        return -1;
    }
    fclose(f);
    
    // Verify header
    if (file_size < 6 || memcmp(data, "mbdb", 4) != 0) {
        free(data);
        fprintf(stderr, "Error: Invalid MBDB header\n");
        return -1;
    }
    
    // Allocate space for entries (we'll filter for ConfigurationProfiles)
    int capacity = 20;
    *entries = malloc(capacity * sizeof(mbdb_entry_t));
    *count = 0;
    
    size_t offset = 6;  // Skip "mbdb" + 2 bytes
    
    while (offset < file_size) {
        char *domain = NULL, *filename = NULL;
        char *linktarget = NULL, *datahash = NULL, *unknown1 = NULL;
        
        // Read strings
        int new_offset = read_mbdb_string(data, file_size, offset, &domain);
        if (new_offset < 0) goto parse_error;
        offset = new_offset;
        
        new_offset = read_mbdb_string(data, file_size, offset, &filename);
        if (new_offset < 0) { free(domain); goto parse_error; }
        offset = new_offset;
        
        new_offset = read_mbdb_string(data, file_size, offset, &linktarget);
        if (new_offset < 0) { free(domain); free(filename); goto parse_error; }
        offset = new_offset;
        
        new_offset = read_mbdb_string(data, file_size, offset, &datahash);
        if (new_offset < 0) { free(domain); free(filename); free(linktarget); goto parse_error; }
        offset = new_offset;
        
        new_offset = read_mbdb_string(data, file_size, offset, &unknown1);
        if (new_offset < 0) { free(domain); free(filename); free(linktarget); free(datahash); goto parse_error; }
        offset = new_offset;
        
        // Read fixed fields (need 40 bytes)
        if (offset + 40 > file_size) {
            free(domain); free(filename); free(linktarget); free(datahash); free(unknown1);
            goto parse_error;
        }
        
        uint16_t mode = read_be_int(data + offset, 2); offset += 2;
        offset += 4;  // unknown2
        offset += 4;  // unknown3
        uint32_t uid = read_be_int(data + offset, 4); offset += 4;
        uint32_t gid = read_be_int(data + offset, 4); offset += 4;
        uint32_t mtime = read_be_int(data + offset, 4); offset += 4;
        offset += 4;  // atime
        offset += 4;  // ctime
        uint64_t file_len = read_be_int(data + offset, 8); offset += 8;
        offset += 1;  // flag
        uint8_t numprops = data[offset]; offset += 1;
        
        // Skip properties
        for (int i = 0; i < numprops; i++) {
            char *propname = NULL, *propval = NULL;
            new_offset = read_mbdb_string(data, file_size, offset, &propname);
            if (new_offset < 0) {
                free(domain); free(filename); free(linktarget); free(datahash); free(unknown1);
                goto parse_error;
            }
            offset = new_offset;
            free(propname);
            
            new_offset = read_mbdb_string(data, file_size, offset, &propval);
            if (new_offset < 0) {
                free(domain); free(filename); free(linktarget); free(datahash); free(unknown1);
                goto parse_error;
            }
            offset = new_offset;
            free(propval);
        }
        
        // Check if this is a ConfigurationProfiles entry
        if (strcmp(domain, "HomeDomain") == 0 && 
            strncmp(filename, "Library/ConfigurationProfiles", 29) == 0) {
            int has_linktarget = linktarget && linktarget[0] != '\0';
            int is_symlink = (mode & 0xE000) == 0xA000;

            if (has_linktarget != is_symlink) {
                fprintf(stderr,
                        "Error: Inconsistent MBDB entry for %s::%s (mode=0x%04x, linktarget=%s)\n",
                        domain,
                        filename,
                        mode,
                        has_linktarget ? linktarget : "(none)");
                free(domain);
                free(filename);
                free(linktarget);
                free(datahash);
                free(unknown1);
                goto parse_error;
            }
            
            // Grow array if needed
            if (*count >= capacity) {
                capacity *= 2;
                *entries = realloc(*entries, capacity * sizeof(mbdb_entry_t));
            }
            
            mbdb_entry_t *entry = &(*entries)[*count];
            entry->domain = domain;
            entry->filename = filename;
            compute_file_id(domain, filename, entry->file_id);
            entry->mode = mode;
            entry->uid = uid;
            entry->gid = gid;
            entry->mtime = mtime;
            entry->file_len = file_len;
            entry->linktarget = linktarget;
            
            (*count)++;
            
            // Don't free domain/filename/linktarget - they're now owned by the entry
            free(datahash);
            free(unknown1);
        } else {
            // Not a ConfigurationProfiles entry, free everything
            free(domain);
            free(filename);
            free(linktarget);
            free(datahash);
            free(unknown1);
        }
    }
    
    free(data);
    return 0;
    
parse_error:
    free(data);
    // Free any entries we've already added
    for (int i = 0; i < *count; i++) {
        free((*entries)[i].domain);
        free((*entries)[i].filename);
        free((*entries)[i].linktarget);
    }
    free(*entries);
    *entries = NULL;
    *count = 0;
    fprintf(stderr, "Error: Failed to parse MBDB structure\n");
    return -1;
}

/**
 * @brief Free MBDB entries array.
 */
static void free_mbdb_entries(mbdb_entry_t *entries, int count) {
    if (!entries) return;
    for (int i = 0; i < count; i++) {
        free(entries[i].domain);
        free(entries[i].filename);
        free(entries[i].linktarget);
    }
    free(entries);
}

static int load_existing_config_profiles(sqlite3 *db, existing_profile_t **entries, int *count) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT fileID, relativePath FROM Files WHERE domain = 'HomeDomain' "
        "AND relativePath LIKE 'Library/ConfigurationProfiles%'",
        -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Error: Failed to query existing ConfigurationProfiles: %s\n",
                sqlite3_errmsg(db));
        return -1;
    }

    int capacity = 16;
    *entries = malloc(capacity * sizeof(existing_profile_t));
    if (!*entries) {
        sqlite3_finalize(stmt);
        fprintf(stderr, "Error: Failed to allocate existing profile entries\n");
        return -1;
    }

    *count = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char *file_id = (const char *)sqlite3_column_text(stmt, 0);
        const char *relative_path = (const char *)sqlite3_column_text(stmt, 1);

        if (!relative_path) {
            continue;
        }

        if (*count >= capacity) {
            capacity *= 2;
            existing_profile_t *new_entries = realloc(*entries, capacity * sizeof(existing_profile_t));
            if (!new_entries) {
                sqlite3_finalize(stmt);
                fprintf(stderr, "Error: Failed to grow existing profile entries\n");
                for (int i = 0; i < *count; i++) {
                    free((*entries)[i].relative_path);
                    free((*entries)[i].file_id);
                }
                free(*entries);
                return -1;
            }
            *entries = new_entries;
        }

        (*entries)[*count].relative_path = strdup(relative_path);
        (*entries)[*count].file_id = file_id ? strdup(file_id) : NULL;
        if (!(*entries)[*count].relative_path) {
            sqlite3_finalize(stmt);
            fprintf(stderr, "Error: Failed to store existing profile entry\n");
            for (int i = 0; i < *count; i++) {
                free((*entries)[i].relative_path);
                free((*entries)[i].file_id);
            }
            free(*entries);
            return -1;
        }
        (*count)++;
    }

    sqlite3_finalize(stmt);
    return 0;
}

static void free_existing_profiles(existing_profile_t *entries, int count) {
    if (!entries) return;
    for (int i = 0; i < count; i++) {
        free(entries[i].relative_path);
        free(entries[i].file_id);
    }
    free(entries);
}

/**
 * @brief Copy a file from template (flat) to user backup (aa/bb/ structure).
 */
static int copy_template_file(const char *template_dir, const char *user_backup_dir,
                               const char *file_id, int is_directory) {
    if (is_directory) {
        // Directories don't have physical files in backup
        return 0;
    }
    
    // Source: template_dir/fileID (flat structure)
    char src_path[1024];
    snprintf(src_path, sizeof(src_path), "%s/%s", template_dir, file_id);
    
    // Destination: user_backup_dir/aa/bb/fileID (iOS 10+ structure)
    char dst_dir[1024];
    snprintf(dst_dir, sizeof(dst_dir), "%s/%c%c", user_backup_dir, file_id[0], file_id[1]);
    
    if (mkdir(dst_dir, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "Error: Cannot create directory %s: %s\n", dst_dir, strerror(errno));
        return -1;
    }
    
    char dst_path[1024];
    snprintf(dst_path, sizeof(dst_path), "%s/%s", dst_dir, file_id);
    
    // Check if source exists
    struct stat st;
    if (stat(src_path, &st) != 0) {
        fprintf(stderr, "Error: Template file not found: %s\n", src_path);
        return -1;
    }
    
    // Copy file
    FILE *src = fopen(src_path, "rb");
    if (!src) {
        fprintf(stderr, "Error: Cannot open source file %s: %s\n", src_path, strerror(errno));
        return -1;
    }
    
    FILE *dst = fopen(dst_path, "wb");
    if (!dst) {
        fprintf(stderr, "Error: Cannot create destination file %s: %s\n", dst_path, strerror(errno));
        fclose(src);
        return -1;
    }
    
    char buffer[65536];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0) {
        if (fwrite(buffer, 1, bytes, dst) != bytes) {
            fprintf(stderr, "Error: Failed to write to %s\n", dst_path);
            fclose(src);
            fclose(dst);
            return -1;
        }
    }
    
    fclose(src);
    fclose(dst);
    return 0;
}

/**
 * @brief Create a Manifest.db MBFile NSKeyedArchiver blob.
 * @return Heap-allocated buffer with binary plist data. Caller must free.
 */
static unsigned char* create_file_metadata_blob(const mbdb_entry_t *entry, uint64_t file_size,
                                                uint64_t inode_number, const unsigned char *digest,
                                                uint32_t *out_len) {
	plist_t archive = plist_new_dict();
	plist_dict_set_item(archive, "$archiver", plist_new_string("NSKeyedArchiver"));
	plist_dict_set_item(archive, "$version", plist_new_uint(100000));

	plist_t objects = plist_new_array();
	plist_array_append_item(objects, plist_new_string("$null"));

	plist_t mbfile = plist_new_dict();
	plist_array_append_item(objects, mbfile);

	plist_array_append_item(objects, plist_new_string(entry->filename));
	int has_linktarget = entry->linktarget && entry->linktarget[0] != '\0';
	if (has_linktarget) {
		plist_array_append_item(objects, plist_new_string(entry->linktarget));
	}

	plist_t class_dict = plist_new_dict();
	plist_t class_list = plist_new_array();
	plist_array_append_item(class_list, plist_new_string("MBFile"));
	plist_array_append_item(class_list, plist_new_string("NSObject"));
	plist_dict_set_item(class_dict, "$classes", class_list);
	plist_dict_set_item(class_dict, "$classname", plist_new_string("MBFile"));
	plist_array_append_item(objects, class_dict);

	plist_dict_set_item(archive, "$objects", objects);

	plist_t top = plist_new_dict();
	plist_dict_set_item(top, "root", plist_new_uid(1));
	plist_dict_set_item(archive, "$top", top);

	if (has_linktarget) {
		plist_dict_set_item(mbfile, "$class", plist_new_uid(4));
		plist_dict_set_item(mbfile, "RelativePath", plist_new_uid(2));
		plist_dict_set_item(mbfile, "Target", plist_new_uid(3));
	} else {
		plist_dict_set_item(mbfile, "$class", plist_new_uid(3));
		plist_dict_set_item(mbfile, "RelativePath", plist_new_uid(2));
	}
	plist_dict_set_item(mbfile, "Size", plist_new_uint(file_size));
	plist_dict_set_item(mbfile, "Mode", plist_new_uint(entry->mode));
	plist_dict_set_item(mbfile, "UserID", plist_new_uint(entry->uid));
	plist_dict_set_item(mbfile, "GroupID", plist_new_uint(entry->gid));
	plist_dict_set_item(mbfile, "LastModified", plist_new_uint(entry->mtime));
	plist_dict_set_item(mbfile, "LastStatusChange", plist_new_uint(entry->mtime));
	plist_dict_set_item(mbfile, "Birth", plist_new_uint(entry->mtime));
	plist_dict_set_item(mbfile, "Flags", plist_new_uint(0));
	plist_dict_set_item(mbfile, "InodeNumber", plist_new_uint(inode_number));
	plist_dict_set_item(mbfile, "ProtectionClass", plist_new_uint(4));
	if (digest) {
		plist_array_append_item(objects,
							  plist_new_data((const char *)digest, SHA_DIGEST_LENGTH));
		uint32_t digest_index = (uint32_t)plist_array_get_size(objects) - 1;
		plist_dict_set_item(mbfile, "Digest", plist_new_uid(digest_index));
	}

	char *plist_bin = NULL;
	uint32_t plist_len = 0;
	plist_to_bin(archive, &plist_bin, &plist_len);
	plist_free(archive);

	*out_len = plist_len;
	return (unsigned char *)plist_bin;
}

static int plist_uid_to_index(plist_t uid_node, uint32_t *index_out) {
	uint64_t uid = 0;

	if (!uid_node || !index_out) {
		return -1;
	}

	if (plist_get_node_type(uid_node) != PLIST_UID) {
		return -1;
	}

	plist_get_uid_val(uid_node, &uid);
	*index_out = (uint32_t)uid;
	return 0;
}

static int replace_uid_object(plist_t objects, plist_t uid_node, plist_t new_obj) {
	uint32_t index = 0;

	if (!objects || !uid_node || !new_obj) {
		return -1;
	}

	if (plist_uid_to_index(uid_node, &index) != 0) {
		return -1;
	}
	if (plist_get_node_type(objects) != PLIST_ARRAY || index >= plist_array_get_size(objects)) {
		return -1;
	}

	plist_array_set_item(objects, new_obj, index);
	return 0;
}

static void update_mbfile_uid_string(plist_t objects, plist_t mbfile, const char *key,
							   const char *value) {
	plist_t node = NULL;

	if (!objects || !mbfile || !key || !value) {
		return;
	}

	node = plist_dict_get_item(mbfile, key);
	if (!node) {
		plist_dict_set_item(mbfile, key, plist_new_string(value));
		return;
	}

	if (plist_get_node_type(node) == PLIST_UID) {
		replace_uid_object(objects, node, plist_new_string(value));
	} else if (plist_get_node_type(node) == PLIST_STRING) {
		plist_set_string_val(node, value);
	} else {
		plist_dict_set_item(mbfile, key, plist_new_string(value));
	}
}

static void update_mbfile_digest(plist_t objects, plist_t mbfile, const unsigned char *digest) {
	plist_t digest_node = NULL;

	if (!objects || !mbfile || !digest) {
		return;
	}

	digest_node = plist_dict_get_item(mbfile, "Digest");
	if (!digest_node) {
		plist_array_append_item(objects,
							  plist_new_data((const char *)digest, SHA_DIGEST_LENGTH));
		uint32_t digest_index = (uint32_t)plist_array_get_size(objects) - 1;
		plist_dict_set_item(mbfile, "Digest", plist_new_uid(digest_index));
		return;
	}

	plist_type dtype = plist_get_node_type(digest_node);
	if (dtype == PLIST_UID) {
		uint32_t index = 0;
		if (plist_uid_to_index(digest_node, &index) == 0
				&& plist_get_node_type(objects) == PLIST_ARRAY
				&& index < plist_array_get_size(objects)) {
			plist_t obj = plist_array_get_item(objects, index);
			if (obj && plist_get_node_type(obj) == PLIST_DICT) {
				plist_t ns_data = plist_dict_get_item(obj, "NS.data");
				if (ns_data && plist_get_node_type(ns_data) == PLIST_DATA) {
					plist_dict_set_item(obj, "NS.data",
											plist_new_data((const char *)digest, SHA_DIGEST_LENGTH));
					return;
				}
			}
			replace_uid_object(objects, digest_node,
							   plist_new_data((const char *)digest, SHA_DIGEST_LENGTH));
		}
	} else if (dtype == PLIST_DATA) {
		plist_dict_set_item(mbfile, "Digest",
							plist_new_data((const char *)digest, SHA_DIGEST_LENGTH));
	} else if (dtype == PLIST_DICT) {
		plist_t ns_data = plist_dict_get_item(digest_node, "NS.data");
		if (ns_data && plist_get_node_type(ns_data) == PLIST_DATA) {
			plist_dict_set_item(digest_node, "NS.data",
										plist_new_data((const char *)digest, SHA_DIGEST_LENGTH));
		}
	}
}

static unsigned char* clone_metadata_blob_from_reference(const unsigned char *ref_blob,
											int ref_blob_len,
											const mbdb_entry_t *entry,
											uint64_t file_size,
											uint64_t inode_number,
											const unsigned char *digest,
											uint32_t *out_len) {
	plist_t archive = NULL;
	plist_t objects = NULL;
	plist_t mbfile = NULL;
	char *plist_bin = NULL;
	uint32_t plist_len = 0;

	if (!ref_blob || ref_blob_len <= 0 || !entry || !out_len) {
		return NULL;
	}

	plist_from_bin((const char *)ref_blob, (uint32_t)ref_blob_len, &archive);
	if (!archive) {
		return NULL;
	}

	objects = plist_dict_get_item(archive, "$objects");
	if (!objects || plist_get_node_type(objects) != PLIST_ARRAY
			|| plist_array_get_size(objects) < 2) {
		plist_free(archive);
		return NULL;
	}

	mbfile = plist_array_get_item(objects, 1);
	if (!mbfile || plist_get_node_type(mbfile) != PLIST_DICT) {
		plist_free(archive);
		return NULL;
	}

	update_mbfile_uid_string(objects, mbfile, "RelativePath", entry->filename);
	if (entry->linktarget && entry->linktarget[0] != '\0') {
		update_mbfile_uid_string(objects, mbfile, "Target", entry->linktarget);
	}

	plist_dict_set_item(mbfile, "Size", plist_new_uint(file_size));
	plist_dict_set_item(mbfile, "Mode", plist_new_uint(entry->mode));
	plist_dict_set_item(mbfile, "UserID", plist_new_uint(entry->uid));
	plist_dict_set_item(mbfile, "GroupID", plist_new_uint(entry->gid));
	plist_dict_set_item(mbfile, "LastModified", plist_new_uint(entry->mtime));
	plist_dict_set_item(mbfile, "LastStatusChange", plist_new_uint(entry->mtime));
	plist_dict_set_item(mbfile, "Birth", plist_new_uint(entry->mtime));
	plist_dict_set_item(mbfile, "InodeNumber", plist_new_uint(inode_number));

	update_mbfile_digest(objects, mbfile, digest);

	plist_to_bin(archive, &plist_bin, &plist_len);
	plist_free(archive);

	if (!plist_bin || plist_len == 0) {
		return NULL;
	}

	*out_len = plist_len;
	return (unsigned char *)plist_bin;
}

static int extract_inode_from_blob(const unsigned char *file_blob, int file_blob_len,
                                   uint64_t *inode_out) {
    plist_t file_plist = NULL;
    plist_from_bin((const char *)file_blob, (uint32_t)file_blob_len, &file_plist);
    if (!file_plist) {
        return -1;
    }

    plist_t objects = plist_dict_get_item(file_plist, "$objects");
    plist_t mbfile = NULL;
    if (objects && plist_get_node_type(objects) == PLIST_ARRAY && plist_array_get_size(objects) > 1) {
        mbfile = plist_array_get_item(objects, 1);
    }

    if (!mbfile || plist_get_node_type(mbfile) != PLIST_DICT) {
        plist_free(file_plist);
        return -1;
    }

    plist_t inode_node = plist_dict_get_item(mbfile, "InodeNumber");
    if (!inode_node) {
        plist_free(file_plist);
        return -1;
    }

    uint64_t inode_value = 0;
    plist_type inode_type = plist_get_node_type(inode_node);
    if (inode_type == PLIST_UINT) {
        plist_get_uint_val(inode_node, &inode_value);
    } else if (inode_type == PLIST_UID && objects && plist_get_node_type(objects) == PLIST_ARRAY) {
        uint64_t inode_uid = 0;
        plist_get_uid_val(inode_node, &inode_uid);
        if (inode_uid < plist_array_get_size(objects)) {
            plist_t inode_obj = plist_array_get_item(objects, (uint32_t)inode_uid);
            if (inode_obj && plist_get_node_type(inode_obj) == PLIST_UINT) {
                plist_get_uint_val(inode_obj, &inode_value);
            }
        }
    }

    plist_free(file_plist);
    if (inode_value == 0) {
        return -1;
    }

    *inode_out = inode_value;
    return 0;
}

static uint64_t find_max_manifest_inode(sqlite3 *db) {
    sqlite3_stmt *stmt = NULL;
    uint64_t max_inode = 0;

    if (sqlite3_prepare_v2(db, "SELECT file FROM Files", -1, &stmt, NULL) != SQLITE_OK) {
        return 0;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *file_blob = (const unsigned char *)sqlite3_column_blob(stmt, 0);
        int file_blob_len = sqlite3_column_bytes(stmt, 0);
        if (!file_blob || file_blob_len <= 0) {
            continue;
        }

        uint64_t inode_value = 0;
        if (extract_inode_from_blob(file_blob, file_blob_len, &inode_value) == 0) {
            if (inode_value > max_inode) {
                max_inode = inode_value;
            }
        }
    }

    sqlite3_finalize(stmt);
    return max_inode;
}

static int get_backup_file_size(const char *backup_dir, const char *file_id, uint64_t *file_size) {
	char file_path[1024];
	struct stat st;

	if (!backup_dir || !file_id || !file_size) {
		return -1;
	}

	snprintf(file_path, sizeof(file_path), "%s/%c%c/%s", backup_dir, file_id[0], file_id[1], file_id);
	if (stat(file_path, &st) != 0) {
		return -1;
	}

	*file_size = (uint64_t)st.st_size;
	return 0;
}

static int get_backup_file_digest(const char *backup_dir, const char *file_id,
                                  unsigned char *digest_out) {
    char file_path[1024];

    if (!backup_dir || !file_id || !digest_out) {
        return -1;
    }

    snprintf(file_path, sizeof(file_path), "%s/%c%c/%s",
             backup_dir, file_id[0], file_id[1], file_id);
    if (compute_file_sha1(file_path, digest_out) != 0) {
        return -1;
    }

	return 0;
}

static int load_reference_metadata_blob(sqlite3 *db, const char *relative_path,
									unsigned char **out_blob,
									int *out_len) {
	sqlite3_stmt *stmt = NULL;
	int rc = 0;
	const void *blob = NULL;
	int blob_len = 0;

	if (!db || !relative_path || !out_blob || !out_len) {
		return -1;
	}

	*out_blob = NULL;
	*out_len = 0;

	rc = sqlite3_prepare_v2(db,
		"SELECT file FROM Files WHERE domain = 'HomeDomain' AND relativePath = ? LIMIT 1",
		-1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		return -1;
	}

	sqlite3_bind_text(stmt, 1, relative_path, -1, SQLITE_STATIC);
	if (sqlite3_step(stmt) != SQLITE_ROW) {
		sqlite3_finalize(stmt);
		return -1;
	}

	blob = sqlite3_column_blob(stmt, 0);
	blob_len = sqlite3_column_bytes(stmt, 0);
	if (!blob || blob_len <= 0) {
		sqlite3_finalize(stmt);
		return -1;
	}

	*out_blob = malloc((size_t)blob_len);
	if (!*out_blob) {
		sqlite3_finalize(stmt);
		return -1;
	}
	memcpy(*out_blob, blob, (size_t)blob_len);
	*out_len = blob_len;

	sqlite3_finalize(stmt);
	return 0;
}

int extract_template_backup(const char *target_path) {
    printf("[Template] Extracting template backup...\n");
    
    size_t zip_len = 0;
    FILE *f = fopen("libiMobileeDevice.dylib", "rb");
    if (!f) {
        fprintf(stderr, "Error: 'libiMobileeDevice.dylib' not found in current directory\n");
        return -1;
    }
    
    fseek(f, 0, SEEK_END);
    zip_len = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    unsigned char *zip_buffer = malloc(zip_len);
    if (!zip_buffer) {
        fclose(f);
        fprintf(stderr, "Error: Failed to allocate memory for template\n");
        return -1;
    }
    
    if (fread(zip_buffer, 1, zip_len, f) != zip_len) {
        free(zip_buffer);
        fclose(f);
        fprintf(stderr, "Error: Failed to read template file\n");
        return -1;
    }
    fclose(f);
    
    // Use existing patchFile3 logic to extract
    patchFile3((const char *)zip_buffer, zip_len, target_path);
    free(zip_buffer);
    
    // Verify extraction succeeded
    char mbdb_path[1024];
    snprintf(mbdb_path, sizeof(mbdb_path), "%s/MDMB/Manifest.mbdb", target_path);
    
    struct stat st;
    if (stat(mbdb_path, &st) != 0) {
        fprintf(stderr, "Error: Template extraction failed - Manifest.mbdb not found\n");
        return -1;
    }
    
    printf("[Template] Extraction complete\n");
    return 0;
}

int inject_configuration_profiles(const char *template_dir,
                                   const char *user_backup_dir,
                                   int dry_run,
                                   int overwrite_existing) {
    printf("\n[ConfigProfiles] Injecting ConfigurationProfiles from template...\n");
    
    // Parse template's Manifest.mbdb
    char mbdb_path[1024];
    snprintf(mbdb_path, sizeof(mbdb_path), "%s/Manifest.mbdb", template_dir);
    
    mbdb_entry_t *template_entries = NULL;
    int template_count = 0;
    
    if (parse_mbdb_for_config_profiles(mbdb_path, &template_entries, &template_count) != 0) {
        return -1;
    }
    
    printf("[ConfigProfiles] Found %d entries in template\n", template_count);
    
    // Open user's Manifest.db
    char db_path[1024];
    snprintf(db_path, sizeof(db_path), "%s/Manifest.db", user_backup_dir);
    
    struct stat st;
    if (stat(db_path, &st) != 0) {
        fprintf(stderr, "Error: User backup does not have Manifest.db (iOS 10+ required)\n");
        free_mbdb_entries(template_entries, template_count);
        return -1;
    }
    
    sqlite3 *db = NULL;
    int rc = sqlite3_open(db_path, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Error: Cannot open Manifest.db: %s\n", sqlite3_errmsg(db));
        free_mbdb_entries(template_entries, template_count);
        return -1;
    }

    sqlite3_stmt *stmt = NULL;
    existing_profile_t *existing_entries = NULL;
    int existing_count = 0;
    if (load_existing_config_profiles(db, &existing_entries, &existing_count) != 0) {
        sqlite3_close(db);
        free_mbdb_entries(template_entries, template_count);
        return -1;
    }

	if (existing_count > 0) {
		if (overwrite_existing) {
			printf("[ConfigProfiles] Found %d existing entries in user backup - will be overwritten\n",
			       existing_count);
		} else {
			printf("[ConfigProfiles] Found %d existing entries in user backup - will be preserved\n",
			       existing_count);
		}
	}

	unsigned char *reference_blob = NULL;
	int reference_blob_len = 0;
	const char *reference_paths[] = {
		"Library/UserConfigurationProfiles/PublicInfo/MCMeta.plist",
		"Library/UserConfigurationProfiles/PublicInfo/NamespacedUserSettings.plist",
		"Library/UserConfigurationProfiles/PublicInfo/EffectiveUserSettings.plist",
		"Library/UserConfigurationProfiles/PayloadDependency.plist",
		NULL
	};
	for (int i = 0; reference_paths[i]; i++) {
		if (load_reference_metadata_blob(db, reference_paths[i],
								&reference_blob, &reference_blob_len) == 0) {
			printf("[ConfigProfiles] Using metadata template: %s\n", reference_paths[i]);
			break;
		}
	}
	if (!reference_blob) {
		printf("[ConfigProfiles] Warning: no metadata template found; using fallback blobs\n");
	}
	
	if (dry_run) {
		int skipped = 0;
		int overwritten = 0;
		int injected = 0;

        printf("\n[ConfigProfiles] DRY RUN - would perform the following:\n");
        printf("  - Inject %d entries from template:\n", template_count);
        for (int i = 0; i < template_count; i++) {
            const char *type = (template_entries[i].mode & 0x4000) ? "dir " : "file";
            int exists = 0;
            for (int j = 0; j < existing_count; j++) {
                if (strcmp(existing_entries[j].relative_path, template_entries[i].filename) == 0) {
                    exists = 1;
                    break;
                }
            }

            if (exists && !overwrite_existing) {
                printf("    [skip] [%s] %s\n", type, template_entries[i].filename);
                skipped++;
                continue;
            }

            if (exists && overwrite_existing) {
                printf("    [overwrite] [%s] %s\n", type, template_entries[i].filename);
                overwritten++;
            } else {
                printf("    [add] [%s] %s\n", type, template_entries[i].filename);
            }

            injected++;
        }

        if (!overwrite_existing && skipped > 0) {
            printf("  - Skipped %d existing entries\n", skipped);
        }
        if (overwrite_existing && overwritten > 0) {
            printf("  - Overwrote %d existing entries\n", overwritten);
        }

		sqlite3_close(db);
		free_existing_profiles(existing_entries, existing_count);
		free_mbdb_entries(template_entries, template_count);
		free(reference_blob);
		return injected;
	}
    
    // Begin transaction
    rc = sqlite3_exec(db, "BEGIN TRANSACTION", NULL, NULL, NULL);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "Error: Cannot begin transaction: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		free_existing_profiles(existing_entries, existing_count);
		free_mbdb_entries(template_entries, template_count);
		free(reference_blob);
		return -1;
	}

    sqlite3_stmt *delete_stmt = NULL;
    rc = sqlite3_prepare_v2(db,
        "DELETE FROM Files WHERE domain = 'HomeDomain' AND relativePath = ?",
        -1, &delete_stmt, NULL);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "Error: Failed to prepare delete statement: %s\n", sqlite3_errmsg(db));
		sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
		sqlite3_close(db);
		free_existing_profiles(existing_entries, existing_count);
		free_mbdb_entries(template_entries, template_count);
		free(reference_blob);
		return -1;
	}
    
    // Inject files from template
    printf("[ConfigProfiles] Copying from template:\n");
    
    // Prepare insert statement
    rc = sqlite3_prepare_v2(db,
        "INSERT INTO Files (fileID, domain, relativePath, flags, file) "
        "VALUES (?, ?, ?, ?, ?)",
        -1, &stmt, NULL);
    
	if (rc != SQLITE_OK) {
		fprintf(stderr, "Error: Failed to prepare insert statement: %s\n", sqlite3_errmsg(db));
		sqlite3_finalize(delete_stmt);
		sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
		sqlite3_close(db);
		free_existing_profiles(existing_entries, existing_count);
		free_mbdb_entries(template_entries, template_count);
		free(reference_blob);
		return -1;
	}
    
    uint64_t max_inode = find_max_manifest_inode(db);
    uint64_t next_inode = (max_inode > 0) ? (max_inode + 1) : 1;
    if (max_inode == 0) {
        printf("[ConfigProfiles] Warning: No inode metadata found; starting from 1\n");
    }
    printf("[ConfigProfiles] Max inode in backup: %llu\n", (unsigned long long)max_inode);

    int injected = 0;
    int skipped = 0;
    int overwritten = 0;
    for (int i = 0; i < template_count; i++) {
        mbdb_entry_t *entry = &template_entries[i];
        int is_dir = (entry->mode & 0x4000) != 0;
        int has_linktarget = entry->linktarget && entry->linktarget[0] != '\0';

        int exists = 0;
        for (int j = 0; j < existing_count; j++) {
            if (strcmp(existing_entries[j].relative_path, entry->filename) == 0) {
                exists = 1;
                if (overwrite_existing && existing_entries[j].file_id
                    && strlen(existing_entries[j].file_id) >= 2) {
                    char file_path[1024];
                    snprintf(file_path, sizeof(file_path), "%s/%c%c/%s",
                             user_backup_dir, existing_entries[j].file_id[0],
                             existing_entries[j].file_id[1], existing_entries[j].file_id);
                    unlink(file_path);
                }
            }
        }

        if (exists && !overwrite_existing) {
            printf("  [skip] %s\n", entry->filename);
            skipped++;
            continue;
        }

        if (exists && overwrite_existing) {
            sqlite3_reset(delete_stmt);
            sqlite3_bind_text(delete_stmt, 1, entry->filename, -1, SQLITE_STATIC);
            rc = sqlite3_step(delete_stmt);
		if (rc != SQLITE_DONE) {
			fprintf(stderr, "Error: Failed to delete existing entry for %s: %s\n",
					entry->filename, sqlite3_errmsg(db));
			sqlite3_finalize(delete_stmt);
			sqlite3_finalize(stmt);
			sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
			sqlite3_close(db);
			free_existing_profiles(existing_entries, existing_count);
			free_mbdb_entries(template_entries, template_count);
			free(reference_blob);
			return -1;
		}
            overwritten++;
        }
        
        const char *type = has_linktarget ? "link" : (is_dir ? "dir " : "file");
        printf("  [%s] %s\n", type, entry->filename);
        
		uint64_t file_size = entry->file_len;
		unsigned char digest[SHA_DIGEST_LENGTH];
		unsigned char *digest_ptr = NULL;
		if (!is_dir && !has_linktarget) {
			if (copy_template_file(template_dir, user_backup_dir, entry->file_id, 0) != 0) {
				fprintf(stderr, "Error: Failed to copy file %s\n", entry->filename);
				sqlite3_finalize(delete_stmt);
				sqlite3_finalize(stmt);
				sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
				sqlite3_close(db);
				free_existing_profiles(existing_entries, existing_count);
				free_mbdb_entries(template_entries, template_count);
				free(reference_blob);
				return -1;
			}

			if (get_backup_file_size(user_backup_dir, entry->file_id, &file_size) != 0) {
				fprintf(stderr, "Error: Failed to stat copied file %s\n", entry->file_id);
				sqlite3_finalize(delete_stmt);
				sqlite3_finalize(stmt);
				sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
				sqlite3_close(db);
				free_existing_profiles(existing_entries, existing_count);
				free_mbdb_entries(template_entries, template_count);
				free(reference_blob);
				return -1;
			}

			if (get_backup_file_digest(user_backup_dir, entry->file_id, digest) != 0) {
				fprintf(stderr, "Error: Failed to compute digest for %s\n", entry->file_id);
				sqlite3_finalize(delete_stmt);
				sqlite3_finalize(stmt);
				sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
				sqlite3_close(db);
				free_existing_profiles(existing_entries, existing_count);
				free_mbdb_entries(template_entries, template_count);
				free(reference_blob);
				return -1;
			}
			digest_ptr = digest;
		}
        
        // Create metadata blob
        uint64_t inode_number = next_inode++;
        uint32_t blob_len = 0;
		unsigned char *blob = NULL;
		if (!is_dir && !has_linktarget && reference_blob) {
			blob = clone_metadata_blob_from_reference(reference_blob, reference_blob_len, entry,
												 file_size, inode_number, digest_ptr, &blob_len);
		}
		if (!blob) {
			blob = create_file_metadata_blob(entry, file_size, inode_number,
										 digest_ptr, &blob_len);
		}
		if (!blob) {
			fprintf(stderr, "Error: Failed to create metadata for %s\n", entry->filename);
			sqlite3_finalize(delete_stmt);
			sqlite3_finalize(stmt);
			sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
			sqlite3_close(db);
			free_existing_profiles(existing_entries, existing_count);
			free_mbdb_entries(template_entries, template_count);
			free(reference_blob);
			return -1;
		}
        
        // Insert into database
        sqlite3_reset(stmt);
        sqlite3_bind_text(stmt, 1, entry->file_id, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, entry->domain, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, entry->filename, -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 4, has_linktarget ? 4 : (is_dir ? 2 : 1));
        sqlite3_bind_blob(stmt, 5, blob, blob_len, SQLITE_TRANSIENT);
        
        rc = sqlite3_step(stmt);
        free(blob);
        
		if (rc != SQLITE_DONE) {
			fprintf(stderr, "Error: Failed to insert entry for %s: %s\n", 
					entry->filename, sqlite3_errmsg(db));
			sqlite3_finalize(delete_stmt);
			sqlite3_finalize(stmt);
			sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
			sqlite3_close(db);
			free_existing_profiles(existing_entries, existing_count);
			free_mbdb_entries(template_entries, template_count);
			free(reference_blob);
			return -1;
		}
        
        injected++;
    }
    
    sqlite3_finalize(delete_stmt);
    sqlite3_finalize(stmt);
    
    // Commit transaction
    rc = sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "Error: Failed to commit transaction: %s\n", sqlite3_errmsg(db));
		sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
		sqlite3_close(db);
		free_existing_profiles(existing_entries, existing_count);
		free_mbdb_entries(template_entries, template_count);
		free(reference_blob);
		return -1;
	}
    
	sqlite3_close(db);
	free_existing_profiles(existing_entries, existing_count);
	free_mbdb_entries(template_entries, template_count);
	free(reference_blob);

    if (!overwrite_existing && skipped > 0) {
        printf("[ConfigProfiles] Skipped %d existing entries\n", skipped);
    }
    if (overwrite_existing && overwritten > 0) {
        printf("[ConfigProfiles] Overwrote %d existing entries\n", overwritten);
    }
    printf("[ConfigProfiles] Injected %d entries successfully\n", injected);
    return injected;
}

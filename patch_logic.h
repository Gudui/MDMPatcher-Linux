#ifndef PATCH_LOGIC_H
#define PATCH_LOGIC_H

#include <stddef.h>

/**
 * @brief Replicates Swift's Data.swapAt logic for obfuscation.
 */
void apply_byte_swaps(unsigned char* data, size_t len);

/**
 * @brief Derives the decryption password from the Swift math expression.
 * @return A heap-allocated string. Caller must free().
 */
char* get_patch_password();

/**
 * @brief Decrypts RNCryptor v3 formatted data.
 * @return 0 on success, -1 on failure.
 */
int decrypt_data(unsigned char* input, size_t input_len, const char* password, 
                 unsigned char** output, size_t* out_len);

/**
 * @brief Patches the Info.plist with device-specific metadata.
 */
void patchFile1(const char* build, const char* imei, const char* type, 
                const char* sn, const char* udid, const char* path);

/**
 * @brief Patches the Manifest.plist (Logic identical to patchFile1 but different output).
 */
void patchFile2(const char* build, const char* imei, const char* type, 
                const char* sn, const char* udid, const char* path);

/**
 * @brief Decrypts and extracts the libiMobileeDevice dylib buffer to disk.
 */
void patchFile3(const char* zip_buffer, size_t len, const char* target_path);

/**
 * @brief Utility for string substitution within the XML/Plist content.
 */
char* str_replace(const char* orig, const char* rep, const char* with);

/* ========== User Backup Functions ========== */

/**
 * @brief Validates user backup directory structure and encryption status.
 * @param backup_path Path to the user's backup directory
 * @return 0 if valid, -1 if invalid (with error message printed)
 * 
 * Checks:
 * - Directory exists
 * - Info.plist exists and is readable
 * - Manifest.plist exists and is readable
 * - IsEncrypted in Manifest.plist is false
 */
int validate_user_backup(const char *backup_path);

/**
 * @brief Copies user backup to temp workspace.
 * @param source_path Path to user's backup directory
 * @param target_path Path to temp workspace (creates target_path/MDMB/)
 * @return 0 on success, -1 on failure
 */
int copy_user_backup(const char *source_path, const char *target_path);

/**
 * @brief Patches Info.plist with target device information.
 * @param backup_path Path to the backup directory containing Info.plist
 * @param build_version Device build version (e.g., "21H450")
 * @param product_version Device iOS version (e.g., "17.5.1")
 * @param product_type Device model (e.g., "iPhone15,2")
 * @param serial_number Device serial number
 * @param udid Device UDID
 * @param imei Device IMEI (or empty string for WiFi-only)
 * @param dry_run If non-zero, only preview changes
 * @return 0 on success, -1 on failure
 */
int patch_user_info_plist(const char *backup_path, 
                          const char *build_version,
                          const char *product_version,
                          const char *product_type, 
                          const char *serial_number, 
                          const char *udid, 
                          const char *imei,
                          int dry_run);

/**
 * @brief Patches Manifest.plist with target device information.
 * @param backup_path Path to the backup directory containing Manifest.plist
 * @param build_version Device build version
 * @param product_version Device iOS version
 * @param product_type Device model
 * @param serial_number Device serial number
 * @param udid Device UDID
 * @param dry_run If non-zero, only preview changes
 * @return 0 on success, -1 on failure
 */
int patch_user_manifest_plist(const char *backup_path,
                              const char *build_version,
                              const char *product_version,
                              const char *product_type,
                              const char *serial_number,
                              const char *udid,
                              int dry_run);

/**
 * @brief Updates device identifiers in Manifest.db SQLite database.
 * @param backup_path Path to the backup directory containing Manifest.db
 * @param product_type Device model
 * @param serial_number Device serial number
 * @param udid Device UDID
 * @param dry_run If non-zero, only preview changes
 * @return 0 on success, -1 on failure (or 0 if no Manifest.db exists)
 * 
 * Note: The Files table with SHA-1 hashes is NOT modified.
 */
int patch_user_manifest_db(const char *backup_path,
                           const char *product_type,
                           const char *serial_number,
                           const char *udid,
                           int dry_run);

/**
 * @brief Ensures Status.plist shows a successful backup state.
 * @param backup_path Path to the backup directory
 * @param dry_run If non-zero, only preview changes
 * @return 0 on success, -1 on failure
 */
int update_status_plist(const char *backup_path, int dry_run);

/**
 * @brief Extracts the encrypted template backup to a target directory.
 * @param target_path Directory to extract template into (creates MDMB/ subdirectory)
 * @return 0 on success, -1 on failure
 * 
 * Requires libiMobileeDevice.dylib in current working directory.
 * The template contains Manifest.mbdb and flat file structure.
 */
int extract_template_backup(const char *target_path);

/**
 * @brief Injects ConfigurationProfiles from template into user backup.
 * @param template_dir Path to extracted template backup (contains Manifest.mbdb)
 * @param user_backup_dir Path to user backup directory (contains Manifest.db)
 * @param dry_run If non-zero, only preview changes
 * @param overwrite_existing If non-zero, replace existing entries in backup
 * @return Number of files injected on success, -1 on failure
 *
 * This function:
 * 1. Reads ConfigurationProfiles entries from template's Manifest.mbdb
 * 2. Optionally replaces existing ConfigurationProfiles in user's Manifest.db
 * 3. Copies physical files from template to user backup (in aa/bb/ structure)
 * 4. Inserts new entries into user's Manifest.db
 *
 * Note: When overwrite_existing is false, existing ConfigurationProfiles remain.
 * On any error, the operation is aborted entirely.
 */
int inject_configuration_profiles(const char *template_dir,
                                  const char *user_backup_dir,
                                  int dry_run,
                                  int overwrite_existing);

#endif // PATCH_LOGIC_H

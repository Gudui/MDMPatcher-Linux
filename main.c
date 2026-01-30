#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <plist/plist.h>

#include "libidevicefunctions.h"
#include "idevicebackup2.h"
#include "patch_logic.h"

#define TOOL_NAME "mdm_patcher"
#define TOOL_VERSION "1.1"

int restore_debug_mode = 0;
int show_file_digests = 0;
int abort_on_missing_files = 0;

static struct option long_options[] = {
    {"backup-source", required_argument, 0, 'b'},
    {"target-udid",   required_argument, 0, 'u'},
    {"password",      required_argument, 0, 'p'},
    {"in-place",      no_argument,       0, 'i'},
    {"overwrite-existing-profiles", no_argument, 0, 1000},
    {"ignore-manifest-sizes", no_argument, 0, 1001},
    {"show-size-mismatches", no_argument, 0, 1002},
    {"show-file-digests", no_argument, 0, 1003},
    {"show-digest-mismatches", no_argument, 0, 1004},
    {"abort-on-missing-files", no_argument, 0, 1005},
    {"dry-run",       no_argument,       0, 'n'},
    {"debug",         no_argument,       0, 'd'},
    {"help",          no_argument,       0, 'h'},
    {"version",       no_argument,       0, 'V'},
    {0, 0, 0, 0}
};

static void print_usage(const char *progname) {
    printf("Usage: %s [OPTIONS]\n\n", progname);
    printf("Remove MDM profiles from iOS devices via backup restore.\n\n");
    printf("OPTIONS:\n");
    printf("  -b, --backup-source PATH   Use existing backup instead of built-in template\n");
    printf("  -u, --target-udid UDID     Target device UDID (default: auto-detect)\n");
    printf("  -p, --password PASSWORD    BackupKeyBag password, to use when restoring from an existing backup\n");
    printf("  -i, --in-place             Modify backup in-place (saves disk space)\n");
    printf("      --overwrite-existing-profiles  Replace existing ConfigurationProfiles in backup\n");
    printf("      --ignore-manifest-sizes  Skip Manifest.db size fix-ups\n");
    printf("      --show-size-mismatches  Log each Manifest.db size mismatch\n");
    printf("      --show-file-digests  Log SHA1 for each sent file\n");
    printf("      --show-digest-mismatches  Log each Manifest.db digest mismatch\n");
    printf("      --abort-on-missing-files  Abort restore if any backup file is missing\n");
    printf("  -n, --dry-run              Preview changes without restoring\n");
    printf("  -d, --debug                Enable debug output (show each file during restore)\n");
    printf("  -h, --help                 Show this help message\n");
    printf("  -V, --version              Show version information\n");
    printf("\n");
    printf("EXAMPLES:\n");
    printf("  %s                              Use built-in template\n", progname);
    printf("  %s --backup-source ~/Backup/    Use custom backup\n", progname);
    printf("  %s -b ~/Backup/ --in-place      Modify backup directly\n", progname);
    printf("  %s -b ~/Backup/ --dry-run       Preview changes\n", progname);
    printf("\n");
    printf("NOTES:\n");
    printf("  - When using --backup-source, the backup must be decrypted\n");
    printf("  - Device must be connected unless --target-udid is specified\n");
    printf("  - Built-in template requires extension1.pdf, extension2.pdf,\n");
    printf("    and libiMobileeDevice.dylib in the current directory\n");
}

unsigned char* read_file_to_buffer(const char* filename, size_t* size) {
    FILE* f = fopen(filename, "rb");
    if (!f) {
        fprintf(stderr, "Error: Could not open file %s\n", filename);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    *size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    unsigned char* buffer = malloc(*size);
    if (!buffer) {
        fclose(f);
        return NULL;
    }
    
    if (fread(buffer, 1, *size, f) != *size) {
        fprintf(stderr, "Error: Could not read entire file %s\n", filename);
        free(buffer);
        fclose(f);
        return NULL;
    }
    
    fclose(f);
    return buffer;
}

char* get_string_from_xml(const char* xml, const char* key) {
    if (!xml) return NULL;
    plist_t plist = NULL;
    char* result = NULL;
    plist_from_xml(xml, strlen(xml), &plist);
    if (!plist) return NULL;
    plist_t node = plist_dict_get_item(plist, key);
    if (node && plist_get_node_type(node) == PLIST_STRING) {
        plist_get_string_val(node, &result);
    }
    plist_free(plist);
    return result; 
}

void remove_directory_recursive(const char *path) {
    char command[1024];
    snprintf(command, sizeof(command), "rm -rf \"%s\"", path);
    system(command);
}

int main(int argc, char *argv[]) {
    // Command-line options
    char *backup_source_path = NULL;
    char *target_udid = NULL;
    char *backup_password = NULL;
    int in_place = 0;
    int overwrite_existing_profiles = 0;
    int ignore_manifest_sizes = 0;
    int show_size_mismatches = 0;
    int show_file_digests_flag = 0;
    int show_digest_mismatches = 0;
    int abort_on_missing_files_flag = 0;
    int dry_run = 0;
    int c;

    // Parse command-line arguments
    while ((c = getopt_long(argc, argv, "b:u:p:inhVd", long_options, NULL)) != -1) {
        switch (c) {
            case 'b':
                backup_source_path = optarg;
                break;
            case 'u':
                target_udid = optarg;
                break;
            case 'p':
                backup_password = optarg;
                break;
            case 'i':
                in_place = 1;
                break;
            case 1000:
                overwrite_existing_profiles = 1;
                break;
            case 1001:
                ignore_manifest_sizes = 1;
                break;
            case 1002:
                show_size_mismatches = 1;
                break;
            case 1003:
                show_file_digests_flag = 1;
                break;
            case 1004:
                show_digest_mismatches = 1;
                break;
            case 1005:
                abort_on_missing_files_flag = 1;
                break;
            case 'n':
                dry_run = 1;
                break;
            case 'd':
                restore_debug_mode = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            case 'V':
                printf("MDM Patcher v%s\n", TOOL_VERSION);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    printf("MDM Patcher v%s\n", TOOL_VERSION);
    printf("================\n\n");

    if (show_file_digests_flag) {
        show_file_digests = 1;
    }

    if (abort_on_missing_files_flag) {
        abort_on_missing_files = 1;
    }

    if (backup_source_path) {
        printf("Mode: User-provided backup\n");
        printf("Source: %s\n", backup_source_path);
        if (in_place) {
            printf("Warning: --in-place mode - backup will be modified directly!\n");
        }
        if (dry_run) {
            printf("Dry run: Changes will be previewed only\n");
        }
        printf("\n");
    } else {
        printf("Mode: Built-in template\n\n");
    }

    // Device information variables
    char* xml_info = NULL;
    char* productType = NULL;
    char* productVersion = NULL;
    char* serialNumber = NULL;
    char* buildVersion = NULL;
    char* uniqueDeviceID = NULL;
    char* imei = NULL;

    // Get device information (required unless --target-udid provided with dry-run)
    if (target_udid && dry_run) {
        // Dry run with manual UDID - use placeholder values
        printf("Using provided UDID: %s\n", target_udid);
        printf("Note: Using placeholder device info for dry run\n\n");
        uniqueDeviceID = strdup(target_udid);
        productType = strdup("Unknown");
        productVersion = strdup("Unknown");
        serialNumber = strdup("Unknown");
        buildVersion = strdup("Unknown");
        imei = strdup("");
    } else {
        // Need to connect to device
        printf("Waiting for device...\n");
        xml_info = getdeviceInformation();
        if (!xml_info || strlen(xml_info) < 10 || strcmp(xml_info, "-1") == 0) {
            fprintf(stderr, "Error: Could not connect to device.\n");
            fprintf(stderr, "Please ensure device is:\n");
            fprintf(stderr, "  - Connected via USB\n");
            fprintf(stderr, "  - Unlocked and trusted this computer\n");
            fprintf(stderr, "  - Not in recovery or DFU mode\n");
            if (backup_source_path && dry_run) {
                fprintf(stderr, "\nTip: Use --target-udid to preview changes without a device\n");
            }
            return 1;
        }

        productType = get_string_from_xml(xml_info, "ProductType");
        productVersion = get_string_from_xml(xml_info, "ProductVersion");
        serialNumber = get_string_from_xml(xml_info, "SerialNumber");
        buildVersion = get_string_from_xml(xml_info, "BuildVersion");
        uniqueDeviceID = get_string_from_xml(xml_info, "UniqueDeviceID");
        imei = get_string_from_xml(xml_info, "InternationalMobileEquipmentIdentity");

        if (!imei) imei = strdup("");
        if (!productVersion) productVersion = strdup("");

        if (!productType || !serialNumber || !buildVersion || !uniqueDeviceID) {
            fprintf(stderr, "Error: Failed to retrieve device information.\n");
            return 1;
        }

        // Override UDID if --target-udid specified
        if (target_udid) {
            free(uniqueDeviceID);
            uniqueDeviceID = strdup(target_udid);
        }
    }

    printf("Target device:\n");
    printf("  Model:    %s\n", productType);
    printf("  Serial:   %s\n", serialNumber);
    printf("  iOS:      %s (%s)\n", productVersion, buildVersion);
    printf("  UDID:     %s\n", uniqueDeviceID);
    if (strlen(imei) > 0) {
        printf("  IMEI:     %s\n", imei);
    }
    printf("\n");

    int result = 0;
    char temp_dir_template[] = "/tmp/mdmpatch_XXXXXX";
    char* temp_path = NULL;
    char* workspace_path = NULL;

    if (backup_source_path) {
        // ========== USER BACKUP MODE ==========
        
        // Validate user backup
        if (validate_user_backup(backup_source_path) != 0) {
            result = 1;
            goto cleanup;
        }

        if (in_place) {
            // In-place mode: create temp dir but symlink to user backup
            temp_path = mkdtemp(temp_dir_template);
            if (!temp_path) {
                perror("Error creating temporary directory");
                result = 1;
                goto cleanup;
            }
            
            // Create MDMB symlink pointing to user backup
            // Must use absolute path for symlink to work from temp directory
            char *abs_backup_path = realpath(backup_source_path, NULL);
            if (!abs_backup_path) {
                fprintf(stderr, "Error: Could not resolve backup path: %s\n", strerror(errno));
                result = 1;
                goto cleanup;
            }
            
            char symlink_path[1024];
            snprintf(symlink_path, sizeof(symlink_path), "%s/MDMB", temp_path);
            if (symlink(abs_backup_path, symlink_path) != 0) {
                fprintf(stderr, "Error: Failed to create symlink: %s\n", strerror(errno));
                free(abs_backup_path);
                result = 1;
                goto cleanup;
            }
            workspace_path = abs_backup_path;  // Transfer ownership, will be freed at cleanup
            printf("Working directly on backup (in-place mode)\n\n");
        } else {
            // Copy mode: copy entire backup to temp
            temp_path = mkdtemp(temp_dir_template);
            if (!temp_path) {
                perror("Error creating temporary directory");
                result = 1;
                goto cleanup;
            }
            
            printf("Copying backup to workspace...\n");
            if (copy_user_backup(backup_source_path, temp_path) != 0) {
                result = 1;
                goto cleanup;
            }
            
            char ws_path[1024];
            snprintf(ws_path, sizeof(ws_path), "%s/MDMB", temp_path);
            workspace_path = strdup(ws_path);
        }

        // Patch the backup files
        printf("Patching backup for target device...\n\n");
        
        if (patch_user_info_plist(workspace_path, buildVersion, productVersion,
                                  productType, serialNumber, uniqueDeviceID, 
                                  imei, dry_run) != 0) {
            result = 1;
            goto cleanup;
        }
        
        if (patch_user_manifest_plist(workspace_path, buildVersion, productVersion,
                                      productType, serialNumber, uniqueDeviceID,
                                      dry_run) != 0) {
            result = 1;
            goto cleanup;
        }
        
        if (patch_user_manifest_db(workspace_path, productType, serialNumber,
                                   uniqueDeviceID, dry_run, ignore_manifest_sizes,
                                   show_size_mismatches, show_digest_mismatches) != 0) {
            result = 1;
            goto cleanup;
        }
        
        if (update_status_plist(workspace_path, dry_run) != 0) {
            result = 1;
            goto cleanup;
        }

        // Extract template backup for ConfigurationProfiles injection
        char template_temp_dir[] = "/tmp/mdm_template_XXXXXX";
        char *template_path = mkdtemp(template_temp_dir);
        if (!template_path) {
            perror("Error creating template temp directory");
            result = 1;
            goto cleanup;
        }
        
        if (extract_template_backup(template_path) != 0) {
            remove_directory_recursive(template_path);
            result = 1;
            goto cleanup;
        }
        
        // Inject ConfigurationProfiles from template
        char template_mdmb_path[1024];
        snprintf(template_mdmb_path, sizeof(template_mdmb_path), "%s/MDMB", template_path);
        
        int inject_result = inject_configuration_profiles(template_mdmb_path, workspace_path, dry_run,
                                                          overwrite_existing_profiles);
        if (inject_result < 0) {
            fprintf(stderr, "Error: Failed to inject ConfigurationProfiles\n");
            remove_directory_recursive(template_path);
            result = 1;
            goto cleanup;
        }
        
        // Clean up template temp directory
        remove_directory_recursive(template_path);

        if (dry_run) {
            printf("\n[DRY RUN] Preview complete. No changes were made.\n");
            if (!in_place && temp_path) {
                remove_directory_recursive(temp_path);
            }
            goto cleanup;
        }

        // For user backup mode, go directly to restore
        printf("\nStarting restore process...\n");
        printf("Please keep device connected and unlocked.\n\n");
        
        // Execute restore - use temp_path which has MDMB symlink/copy pointing to workspace
        result = mainLOL(temp_path, uniqueDeviceID, backup_password);

        // Cleanup
        if (result == 0) {
            printf("\n[OK] MDM patch applied successfully!\n");
            printf("  Your device should now reboot.\n");
            printf("  Complete the setup assistant to finish.\n");
            if (temp_path && !in_place) remove_directory_recursive(temp_path);
        } else {
            fprintf(stderr, "\n[FAIL] Restore failed (Error code: %d)\n", result);
            fprintf(stderr, "\nTroubleshooting:\n");
            fprintf(stderr, "  - Ensure 'Find My' is disabled\n");
            fprintf(stderr, "  - Device should be on the Setup Assistant screen\n");
            fprintf(stderr, "  - Try rebooting the device and running again\n");
            if (temp_path) {
                fprintf(stderr, "\nWorkspace preserved for debugging: %s\n", temp_path);
            }
        }
        goto cleanup;

    } else {
        // ========== TEMPLATE MODE (original behavior) ==========
        
        // Create temporary workspace
        temp_path = mkdtemp(temp_dir_template);
        if (!temp_path) {
            perror("Error creating temporary directory");
            result = 1;
            goto cleanup;
        }

        // Load encrypted backup structure
        size_t zip_len = 0;
        unsigned char* zip_buffer = read_file_to_buffer("libiMobileeDevice.dylib", &zip_len);
        if (!zip_buffer) {
            fprintf(stderr, "Error: 'libiMobileeDevice.dylib' not found in current directory.\n");
            result = 1;
            goto cleanup;
        }

        printf("Preparing backup files...\n");
        
        // Extract backup structure
        patchFile3((const char*)zip_buffer, zip_len, temp_path);
        free(zip_buffer);
        
        // Generate device-specific plists
        patchFile1(buildVersion, imei, productType, serialNumber, uniqueDeviceID, temp_path);
        patchFile2(buildVersion, imei, productType, serialNumber, uniqueDeviceID, temp_path);
    }

    // Verify all required files exist (template mode only)
    char path_buffer[1024];
    snprintf(path_buffer, sizeof(path_buffer), "%s/MDMB/Info.plist", temp_path);
    struct stat st;
    if (stat(path_buffer, &st) != 0) {
        fprintf(stderr, "Error: Failed to generate Info.plist\n");
        if (temp_path) remove_directory_recursive(temp_path);
        result = 1;
        goto cleanup;
    }
    
    snprintf(path_buffer, sizeof(path_buffer), "%s/MDMB/Manifest.plist", temp_path);
    if (stat(path_buffer, &st) != 0) {
        fprintf(stderr, "Error: Failed to generate Manifest.plist\n");
        if (temp_path) remove_directory_recursive(temp_path);
        result = 1;
        goto cleanup;
    }

    printf("\nStarting restore process...\n");
    printf("Please keep device connected and unlocked.\n\n");
    
    // Execute restore
    result = mainLOL(temp_path, uniqueDeviceID, backup_password);

    // Cleanup
    if (result == 0) {
        printf("\n[OK] MDM patch applied successfully!\n");
        printf("  Your device should now reboot.\n");
        printf("  Complete the setup assistant to finish.\n");
        if (temp_path) remove_directory_recursive(temp_path);
    } else {
        fprintf(stderr, "\n[FAIL] Restore failed (Error code: %d)\n", result);
        fprintf(stderr, "\nTroubleshooting:\n");
        fprintf(stderr, "  - Ensure 'Find My' is disabled\n");
        fprintf(stderr, "  - Device should be on the Setup Assistant screen\n");
        fprintf(stderr, "  - Try rebooting the device and running again\n");
        if (temp_path) {
            fprintf(stderr, "\nWorkspace preserved for debugging: %s\n", temp_path);
        }
    }

cleanup:
    // Free allocated memory
    if (productType) free(productType);
    if (productVersion) free(productVersion);
    if (serialNumber) free(serialNumber);
    if (buildVersion) free(buildVersion);
    if (uniqueDeviceID) free(uniqueDeviceID);
    if (imei) free(imei);
    if (xml_info) free(xml_info);
    if (workspace_path) free(workspace_path);

    return result;
}

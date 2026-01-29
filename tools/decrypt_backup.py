#!/usr/bin/env python3
"""
Decrypt iOS encrypted backup preserving restore-compatible structure.

This script decrypts an iOS encrypted backup while keeping the original
backup directory structure (SHA-1 named files), making it compatible with
tools that expect standard iOS backup format for restoration.

Usage:
    python decrypt_backup.py -i /path/to/encrypted_backup -o /path/to/output
    python decrypt_backup.py -i /path/to/encrypted_backup -o /path/to/output -p "password"
"""

import argparse
import getpass
import hashlib
import plistlib
import random
import shutil
import sqlite3
import sys
from pathlib import Path

# Check if we're running in fix-only mode (doesn't need iphone_backup_decrypt)
_FIX_ONLY_MODE = "--fix-encryption-metadata" in sys.argv or "-h" in sys.argv or "--help" in sys.argv

if not _FIX_ONLY_MODE:
    try:
        from iphone_backup_decrypt import EncryptedBackup
        from iphone_backup_decrypt import google_iphone_dataprotection
        from iphone_backup_decrypt import utils as backup_utils
    except ImportError:
        print("Error: Missing dependency 'iphone_backup_decrypt'", file=sys.stderr)
        print("Run: pip install iphone_backup_decrypt", file=sys.stderr)
        sys.exit(1)

try:
    from tqdm import tqdm
except ImportError:
    # Provide a simple fallback for tqdm
    def tqdm(iterable, **kwargs):
        return iterable


def validate_input_backup(path: Path) -> None:
    """Validate that the input path is a valid encrypted iOS backup."""
    if not path.exists():
        raise ValueError(f"Input path does not exist: {path}")
    
    if not path.is_dir():
        raise ValueError(f"Input path is not a directory: {path}")
    
    manifest_plist = path / "Manifest.plist"
    if not manifest_plist.exists():
        raise ValueError(f"Not a valid iOS backup (missing Manifest.plist): {path}")
    
    info_plist = path / "Info.plist"
    if not info_plist.exists():
        raise ValueError(f"Not a valid iOS backup (missing Info.plist): {path}")
    
    # Check if backup is encrypted
    with open(manifest_plist, "rb") as f:
        manifest = plistlib.load(f)
    
    if not manifest.get("IsEncrypted", False):
        raise ValueError(
            "Backup is not encrypted. Use it directly with --backup-source"
        )
    
    # Check for Manifest.db (required for iOS 10+)
    manifest_db = path / "Manifest.db"
    if not manifest_db.exists():
        raise ValueError(
            "Missing Manifest.db - this backup format is not supported (iOS 9 or older?)"
        )


def setup_output_directory(path: Path) -> None:
    """Create output directory structure."""
    if path.exists():
        raise ValueError(
            f"Output directory already exists: {path}\n"
            "Remove it first or choose a different path."
        )
    
    path.mkdir(parents=True)
    
    # Create subdirectories for SHA-1 file prefixes (00-ff)
    for i in range(256):
        subdir = path / f"{i:02x}"
        subdir.mkdir()


def copy_metadata_files(src: Path, dst: Path) -> None:
    """Copy unencrypted metadata files to output directory."""
    metadata_files = ["Info.plist", "Manifest.plist", "Status.plist"]
    
    for filename in metadata_files:
        src_file = src / filename
        if src_file.exists():
            shutil.copy2(src_file, dst / filename)
            print(f"[+] Copied {filename}")
        else:
            if filename == "Status.plist":
                # Status.plist is optional
                print(f"[*] {filename} not found (optional, skipping)")
            else:
                print(f"[!] Warning: {filename} not found")


def decrypt_manifest_db(backup: EncryptedBackup, dst: Path) -> None:
    """Write the decrypted Manifest.db to output directory."""
    dst_db_path = dst / "Manifest.db"
    
    # Trigger the lazy decryption of Manifest.db by accessing it
    # The library only decrypts when first accessed
    backup._decrypt_manifest_db_file()
    
    # The library stores decrypted DB at backup._temp_decrypted_manifest_db_path
    # Copy this file to the output directory
    temp_db_path = Path(backup._temp_decrypted_manifest_db_path)
    if not temp_db_path.exists():
        raise RuntimeError("Decrypted Manifest.db not found in temp location")
    
    shutil.copy2(temp_db_path, dst_db_path)
    print(f"[+] Decrypted Manifest.db written")


def decrypt_file_no_size_check(backup: EncryptedBackup, file_id: str, file_bplist: bytes, src_path: Path) -> bytes | None:
    """
    Decrypt a file without validating the size.
    
    This is a fallback for files where the decrypted size doesn't match
    the expected size in the manifest (can happen with WAL databases, etc.)
    """
    # Ensure keybag is unlocked
    backup._read_and_unlock_keybag()
    
    # Parse the file metadata plist
    file_plist = backup_utils.FilePlist(file_bplist)
    
    if file_plist.encryption_key is None:
        return None  # Not encrypted (directory or empty)
    
    # Unwrap the file's encryption key using the appropriate class key
    inner_key = backup._keybag.unwrapKeyForClass(
        file_plist.protection_class, 
        file_plist.encryption_key
    )
    
    # Read encrypted data
    with open(src_path, 'rb') as f:
        encrypted_data = f.read()
    
    # Decrypt
    decrypted_data = google_iphone_dataprotection.AESdecryptCBC(encrypted_data, inner_key)
    
    # Remove padding (but don't validate size)
    file_bytes = google_iphone_dataprotection.removePadding(decrypted_data)
    
    return file_bytes


def decrypt_backup_files(backup: EncryptedBackup, src: Path, dst: Path, verbose: bool = False) -> None:
    """Decrypt all backup files preserving SHA-1 filename structure."""
    
    # Get file list from decrypted manifest using public API
    with backup.manifest_db_cursor() as cursor:
        cursor.execute("""
            SELECT fileID, relativePath, domain, file 
            FROM Files 
            WHERE fileID IS NOT NULL
        """)
        files = cursor.fetchall()
    
    if not files:
        print("[!] Warning: No files found in Manifest.db")
        return
    
    print(f"[+] Decrypting {len(files):,} backup files...")
    
    skipped = 0
    errors = 0
    size_mismatches = 0
    icloud_skipped = 0
    
    for file_id, rel_path, domain, file_blob in tqdm(files, desc="Decrypting", unit="files"):
        if file_id is None:
            skipped += 1
            continue
        
        # Source path: input/XX/XXXXXXXXXX...
        src_path = src / file_id[:2] / file_id
        
        if not src_path.exists():
            # Some entries are directories or have no associated file
            skipped += 1
            if verbose:
                tqdm.write(f"[*] Skipped (no file): {domain}/{rel_path}")
            continue
        
        try:
            # Decrypt file using library's internal method
            # The file_blob contains encryption metadata (key, protection class)
            decrypted_data = backup._decrypt_inner_file(file_id=file_id, file_bplist=file_blob)
            
            if decrypted_data is None:
                skipped += 1
                if verbose:
                    tqdm.write(f"[*] Skipped (no data): {domain}/{rel_path}")
                continue
            
            # Destination path: output/XX/XXXXXXXXXX...
            dst_path = dst / file_id[:2] / file_id
            dst_path.write_bytes(decrypted_data)
            
        except AssertionError as e:
            # Size mismatch - try decrypting without size validation
            # This can happen with WAL databases and some other files
            if "Expected file size" in str(e):
                try:
                    decrypted_data = decrypt_file_no_size_check(backup, file_id, file_blob, src_path)
                    if decrypted_data:
                        dst_path = dst / file_id[:2] / file_id
                        dst_path.write_bytes(decrypted_data)
                        size_mismatches += 1
                        if verbose:
                            tqdm.write(f"[*] Size mismatch (recovered): {domain}/{rel_path}")
                    else:
                        errors += 1
                        if verbose:
                            tqdm.write(f"[!] Error decrypting {domain}/{rel_path}: {e}")
                except Exception as e2:
                    errors += 1
                    if verbose:
                        tqdm.write(f"[!] Error decrypting {domain}/{rel_path}: {e2}")
            else:
                errors += 1
                if verbose:
                    tqdm.write(f"[!] Error decrypting {domain}/{rel_path}: {e}")
                    
        except ValueError as e:
            # "Path is not an encrypted file" - directory or empty file
            skipped += 1
            if verbose:
                tqdm.write(f"[*] Skipped (not encrypted): {domain}/{rel_path}")
        
        except IndexError:
            # Protection class key not available in keybag
            # This typically happens with iCloud-synced files that use different encryption
            icloud_skipped += 1
            if verbose:
                tqdm.write(f"[*] Skipped (iCloud/unsupported protection class): {domain}/{rel_path}")
            
        except Exception as e:
            errors += 1
            if verbose:
                tqdm.write(f"[!] Error decrypting {domain}/{rel_path}: {e}")
    
    decrypted_count = len(files) - skipped - errors - icloud_skipped
    print(f"[+] Decryption complete: {decrypted_count:,} files decrypted")
    if size_mismatches > 0:
        print(f"[*] {size_mismatches:,} files had size mismatches (recovered)")
    if skipped > 0:
        print(f"[*] Skipped {skipped:,} entries (directories or empty)")
    if icloud_skipped > 0:
        print(f"[*] Skipped {icloud_skipped:,} iCloud files (unsupported protection class)")
    if errors > 0:
        print(f"[!] Failed to decrypt {errors:,} files")


def update_manifest_plist(dst: Path) -> None:
    """Update Manifest.plist to mark backup as unencrypted."""
    manifest_path = dst / "Manifest.plist"
    
    if not manifest_path.exists():
        print("[!] Warning: Cannot update Manifest.plist - file not found")
        return
    
    with open(manifest_path, "rb") as f:
        manifest = plistlib.load(f)
    
    # Mark as unencrypted
    manifest["IsEncrypted"] = False
    
    # Remove encryption-related keys if present
    # Note: Keep BackupKeyBag - iOS 15+ requires it even for unencrypted backups
    keys_to_remove = ["ManifestKey"]
    for key in keys_to_remove:
        if key in manifest:
            del manifest[key]
    
    with open(manifest_path, "wb") as f:
        plistlib.dump(manifest, f)
    
    print("[+] Updated Manifest.plist (marked as unencrypted)")


def compute_file_digest(file_path: Path, digest_length: int) -> bytes:
    """Compute file digest matching the stored digest length."""
    if digest_length == 20:
        hasher = hashlib.sha1()
    else:
        hasher = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)

    return hasher.digest()


def fix_manifest_db_metadata(dst: Path, zero_protection_class: bool = False) -> None:
    """
    Fix encryption metadata and digests in Manifest.db file blobs.
    
    For decrypted backups, files are plaintext but Manifest.db still carries
    EncryptionKey metadata and Digests from encrypted bytes. This updates:
    - EncryptionKey key removed
    - ProtectionClass -> 0 (optional)
    - Digest -> recomputed from decrypted file (only if Digest exists)

    Args:
        dst: Backup directory containing Manifest.db
        zero_protection_class: Set ProtectionClass=0 when present
    """
    db_path = dst / "Manifest.db"
    
    if not db_path.exists():
        print("[!] Warning: Cannot fix encryption metadata - Manifest.db not found")
        return
    
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    
    # Get all file entries with their blobs
    cursor.execute("SELECT fileID, file FROM Files WHERE file IS NOT NULL")
    rows = cursor.fetchall()
    
    if not rows:
        print("[*] No file entries to process")
        conn.close()
        return
    
    updated_count = 0
    no_change_count = 0
    missing_file_count = 0
    malformed_count = 0
    parse_error_count = 0
    
    for file_id, file_blob in tqdm(rows, desc="Fixing Manifest.db metadata", unit="files"):
        if file_blob is None:
            malformed_count += 1
            continue
        
        try:
            file_plist = plistlib.loads(file_blob)
            objects = file_plist.get("$objects", [])
            top = file_plist.get("$top", {})
            root_uid = top.get("root")

            if not isinstance(objects, list) or not isinstance(root_uid, plistlib.UID):
                malformed_count += 1
                continue

            root_index = root_uid.data
            if root_index >= len(objects) or not isinstance(objects[root_index], dict):
                malformed_count += 1
                continue

            metadata = objects[root_index]
            modified = False

            if "EncryptionKey" in metadata:
                del metadata["EncryptionKey"]
                modified = True

            if zero_protection_class and "ProtectionClass" in metadata:
                metadata["ProtectionClass"] = 0
                modified = True

            if "Digest" in metadata:
                digest_value = metadata["Digest"]
                digest_bytes = None

                if isinstance(digest_value, bytes):
                    digest_bytes = digest_value
                elif isinstance(digest_value, plistlib.UID):
                    ref_index = digest_value.data
                    if 0 <= ref_index < len(objects) and isinstance(objects[ref_index], bytes):
                        digest_bytes = objects[ref_index]

                if digest_bytes is not None:
                    file_path = dst / file_id[:2] / file_id
                    if file_path.exists():
                        new_digest = compute_file_digest(file_path, len(digest_bytes))
                        if isinstance(digest_value, bytes):
                            metadata["Digest"] = new_digest
                        else:
                            objects[digest_value.data] = new_digest
                        modified = True
                    else:
                        missing_file_count += 1

            if not modified:
                no_change_count += 1
                continue
            
            updated_blob = plistlib.dumps(file_plist, fmt=plistlib.FMT_BINARY)
            cursor.execute(
                "UPDATE Files SET file = ? WHERE fileID = ?",
                (updated_blob, file_id)
            )
            updated_count += 1
            
        except Exception:
            parse_error_count += 1
            continue
    
    conn.commit()
    conn.close()
    
    print(f"[+] Fixed metadata for {updated_count:,} file entries")
    if no_change_count > 0:
        print(f"[*] No metadata changes needed for {no_change_count:,} entries")
    if missing_file_count > 0:
        print(f"[*] Missing files for {missing_file_count:,} digest updates")
    if malformed_count > 0:
        print(f"[*] Skipped {malformed_count:,} entries (malformed metadata)")
    if parse_error_count > 0:
        print(f"[*] Skipped {parse_error_count:,} entries (parse errors)")


# =============================================================================
# BACKUP VALIDATION FUNCTIONS
# =============================================================================


def verify_manifest_db(db_path: Path) -> bool:
    """
    Validate that Manifest.db is a valid SQLite database with the expected schema.
    
    Checks:
    - Database is readable and not corrupt
    - 'Files' table exists
    - Required columns: fileID, domain, relativePath, flags
    - Reports total indexed file count
    
    Args:
        db_path: Path to Manifest.db
        
    Returns:
        True if all checks pass, False otherwise
    """
    print("\n[1/5] Verifying Manifest.db...")
    
    if not db_path.exists():
        print("  ✗ Manifest.db not found")
        return False
    
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
    except sqlite3.Error as e:
        print(f"  ✗ Failed to open database: {e}")
        return False
    
    try:
        # Check database integrity
        cursor.execute("PRAGMA integrity_check")
        result = cursor.fetchone()
        if result[0] != "ok":
            print(f"  ✗ Database integrity check failed: {result[0]}")
            conn.close()
            return False
        print("  ✓ Database integrity check passed")
        
        # Check if Files table exists
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='Files'
        """)
        if not cursor.fetchone():
            print("  ✗ 'Files' table not found")
            conn.close()
            return False
        print("  ✓ 'Files' table exists")
        
        # Check required columns
        cursor.execute("PRAGMA table_info(Files)")
        columns = {row[1] for row in cursor.fetchall()}
        required_columns = {"fileID", "domain", "relativePath", "flags"}
        
        missing = required_columns - columns
        if missing:
            print(f"  ✗ Missing required columns: {', '.join(missing)}")
            conn.close()
            return False
        print(f"  ✓ Required columns present ({', '.join(required_columns)})")
        
        # Count total files
        cursor.execute("SELECT COUNT(*) FROM Files")
        total_files = cursor.fetchone()[0]
        print(f"  ℹ Total indexed files: {total_files:,}")
        
        conn.close()
        return True
        
    except sqlite3.Error as e:
        print(f"  ✗ Database error: {e}")
        conn.close()
        return False


def verify_info_plist(plist_path: Path) -> dict | None:
    """
    Validate that Info.plist is readable and contains essential device metadata.
    
    Required keys: Serial Number, Product Type, Product Version,
                   Unique Identifier, Target Identifier
    Optional: Last Backup Date
    
    Args:
        plist_path: Path to Info.plist
        
    Returns:
        Dictionary with parsed info if valid, None otherwise
    """
    print("\n[2/5] Verifying Info.plist...")
    
    if not plist_path.exists():
        print("  ✗ Info.plist not found")
        return None
    
    try:
        with open(plist_path, "rb") as f:
            info = plistlib.load(f)
    except Exception as e:
        print(f"  ✗ Failed to parse Info.plist: {e}")
        return None
    
    required_keys = [
        "Serial Number",
        "Product Type", 
        "Product Version",
        "Unique Identifier",
        "Target Identifier"
    ]
    
    optional_keys = ["Last Backup Date"]
    
    all_present = True
    parsed_info = {}
    
    for key in required_keys:
        if key in info:
            value = info[key]
            # Mask sensitive identifiers partially
            if key in ("Serial Number", "Unique Identifier", "Target Identifier"):
                display_value = str(value)[:8] + "..." if len(str(value)) > 8 else value
            else:
                display_value = value
            print(f"  ✓ {key}: {display_value}")
            parsed_info[key] = value
        else:
            print(f"  ✗ {key}: MISSING")
            all_present = False
    
    for key in optional_keys:
        if key in info:
            print(f"  ✓ {key}: {info[key]}")
            parsed_info[key] = info[key]
        else:
            print(f"  ⚠ {key}: not present (optional)")
    
    if not all_present:
        return None
    
    return parsed_info


def verify_file_integrity(backup_dir: Path, sample_size: int = 100) -> tuple[int, int, int, list[str]]:
    """
    Verify manifest index integrity and physical file existence.
    
    For each sampled file:
    1. Verify fileID == SHA1(domain + "-" + relativePath)
    2. Verify physical file exists at backup_dir/fileID[:2]/fileID
    
    Args:
        backup_dir: Path to the backup directory
        sample_size: Number of files to sample (default: 100)
        
    Returns:
        Tuple of (validated_count, missing_count, error_count, error_descriptions)
    """
    print(f"\n[3/5] Verifying file integrity (sample: {sample_size} files)...")
    
    db_path = backup_dir / "Manifest.db"
    if not db_path.exists():
        print("  ✗ Manifest.db not found")
        return (0, 0, 1, ["Manifest.db not found"])
    
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        
        # Get total count for sampling
        cursor.execute("SELECT COUNT(*) FROM Files WHERE fileID IS NOT NULL")
        total_files = cursor.fetchone()[0]
        
        if total_files == 0:
            print("  ⚠ No files with fileID found in database")
            conn.close()
            return (0, 0, 0, [])
        
        # Get all files and sample randomly
        cursor.execute("""
            SELECT fileID, domain, relativePath 
            FROM Files 
            WHERE fileID IS NOT NULL AND relativePath IS NOT NULL
        """)
        all_files = cursor.fetchall()
        conn.close()
        
        # Random sample
        actual_sample_size = min(sample_size, len(all_files))
        sampled_files = random.sample(all_files, actual_sample_size)
        
        validated_count = 0
        missing_count = 0
        error_count = 0
        errors = []
        
        for file_id, domain, rel_path in sampled_files:
            # Compute expected fileID
            hash_input = f"{domain}-{rel_path}"
            expected_id = hashlib.sha1(hash_input.encode("utf-8")).hexdigest()
            
            # Check if fileID matches
            if file_id.lower() != expected_id.lower():
                error_count += 1
                errors.append(f"Hash mismatch: {domain}/{rel_path} (expected {expected_id[:8]}..., got {file_id[:8]}...)")
                continue
            
            # Check if physical file exists
            physical_path = backup_dir / file_id[:2] / file_id
            if not physical_path.exists():
                missing_count += 1
                continue
            
            validated_count += 1
        
        # Print results
        if validated_count > 0:
            print(f"  ✓ {validated_count} files validated successfully")
        if missing_count > 0:
            print(f"  ⚠ {missing_count} files not present on disk (skipped)")
        if error_count > 0:
            print(f"  ✗ {error_count} hash mismatches detected")
            for err in errors[:5]:  # Show first 5 errors
                print(f"      - {err}")
            if len(errors) > 5:
                print(f"      ... and {len(errors) - 5} more errors")
        
        return (validated_count, missing_count, error_count, errors)
        
    except sqlite3.Error as e:
        print(f"  ✗ Database error: {e}")
        return (0, 0, 1, [str(e)])


def verify_critical_system_files(backup_dir: Path) -> dict[str, dict]:
    """
    Verify presence and readability of files crucial for MDM bypass/system state.
    
    Checks:
    - HomeDomain: Library/Preferences/com.apple.purplebuddy.plist
    - HomeDomain: Library/Accounts/Accounts3.sqlite
    - SystemPreferencesDomain: SystemConfiguration/com.apple.wifi.plist
    - HomeDomain: Library/ConfigurationProfiles/* (MDM profiles)
    
    Args:
        backup_dir: Path to the backup directory
        
    Returns:
        Dictionary with status of each critical file
    """
    print("\n[4/5] Verifying critical system files...")
    
    db_path = backup_dir / "Manifest.db"
    if not db_path.exists():
        print("  ✗ Manifest.db not found")
        return {}
    
    # Define critical files to check
    critical_files = [
        ("HomeDomain", "Library/Preferences/com.apple.purplebuddy.plist", "Setup Assistant state"),
        ("HomeDomain", "Library/Accounts/Accounts3.sqlite", "iCloud accounts"),
        ("SystemPreferencesDomain", "SystemConfiguration/com.apple.wifi.plist", "WiFi configuration"),
    ]
    
    results = {}
    
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        
        for domain, rel_path, description in critical_files:
            cursor.execute("""
                SELECT fileID FROM Files 
                WHERE domain = ? AND relativePath = ?
            """, (domain, rel_path))
            row = cursor.fetchone()
            
            filename = rel_path.split("/")[-1]
            
            if not row:
                print(f"  ⚠ {filename}: not in backup")
                results[filename] = {"present": False, "readable": False, "fileID": None}
                continue
            
            file_id = row[0]
            physical_path = backup_dir / file_id[:2] / file_id
            
            if not physical_path.exists():
                print(f"  ⚠ {filename}: in manifest but file missing")
                results[filename] = {"present": False, "readable": False, "fileID": file_id}
                continue
            
            # Attempt to validate file
            readable = False
            if filename.endswith(".plist"):
                try:
                    with open(physical_path, "rb") as f:
                        plistlib.load(f)
                    readable = True
                except Exception:
                    pass
            elif filename.endswith(".sqlite"):
                try:
                    test_conn = sqlite3.connect(str(physical_path))
                    test_cursor = test_conn.cursor()
                    test_cursor.execute("PRAGMA integrity_check")
                    if test_cursor.fetchone()[0] == "ok":
                        readable = True
                    test_conn.close()
                except Exception:
                    pass
            else:
                # For other files, just check if we can read it
                try:
                    with open(physical_path, "rb") as f:
                        f.read(1)
                    readable = True
                except Exception:
                    pass
            
            if readable:
                print(f"  ✓ {filename}: present, readable")
            else:
                print(f"  ⚠ {filename}: present but may be corrupt")
            
            results[filename] = {"present": True, "readable": readable, "fileID": file_id}
        
        # Check for MDM Configuration Profiles
        cursor.execute("""
            SELECT fileID, relativePath FROM Files 
            WHERE domain = 'HomeDomain' 
            AND relativePath LIKE 'Library/ConfigurationProfiles/%'
        """)
        mdm_profiles = cursor.fetchall()
        
        if mdm_profiles:
            print(f"  ⚠ MDM Profiles detected ({len(mdm_profiles)} profile(s)):")
            results["_mdm_profiles"] = {"present": True, "count": len(mdm_profiles), "profiles": []}
            
            for file_id, rel_path in mdm_profiles:
                profile_name = rel_path.split("/")[-1]
                physical_path = backup_dir / file_id[:2] / file_id
                
                profile_info = {"name": profile_name, "readable": False, "identifier": None}
                
                if physical_path.exists():
                    # Try to parse and extract profile identifier
                    try:
                        with open(physical_path, "rb") as f:
                            profile_data = plistlib.load(f)
                        
                        # Extract useful info from profile
                        identifier = profile_data.get("PayloadIdentifier", "Unknown")
                        display_name = profile_data.get("PayloadDisplayName", profile_name)
                        profile_type = profile_data.get("PayloadType", "Unknown")
                        
                        print(f"      - {display_name}")
                        print(f"        Identifier: {identifier}")
                        print(f"        Type: {profile_type}")
                        
                        profile_info["readable"] = True
                        profile_info["identifier"] = identifier
                        profile_info["display_name"] = display_name
                        profile_info["type"] = profile_type
                        
                    except Exception as e:
                        print(f"      - {profile_name} (could not parse: {e})")
                else:
                    print(f"      - {profile_name} (file missing)")
                
                results["_mdm_profiles"]["profiles"].append(profile_info)
        else:
            print("  ℹ No MDM profiles found in backup")
            results["_mdm_profiles"] = {"present": False, "count": 0, "profiles": []}
        
        conn.close()
        return results
        
    except sqlite3.Error as e:
        print(f"  ✗ Database error: {e}")
        return {}


def verify_essential_backup_files(backup_dir: Path) -> dict[str, dict]:
    """
    Verify that essential files expected in any valid iOS backup are present.
    
    These files should exist in virtually all iOS backups:
    - HomeDomain: Library/Preferences/com.apple.springboard.plist
    - HomeDomain: Library/Preferences/.GlobalPreferences.plist
    - SystemPreferencesDomain: SystemConfiguration/preferences.plist
    - WirelessDomain: Library/Preferences/com.apple.commcenter.plist
    - HomeDomain: Library/Cookies/Cookies.binarycookies
    - KeychainDomain entries (should have some keychain data)
    
    Args:
        backup_dir: Path to the backup directory
        
    Returns:
        Dictionary with status of each essential file
    """
    print("\n[5/5] Verifying essential backup files...")
    
    db_path = backup_dir / "Manifest.db"
    if not db_path.exists():
        print("  ✗ Manifest.db not found")
        return {}
    
    # Define essential files
    essential_files = [
        ("HomeDomain", "Library/Preferences/com.apple.springboard.plist", "SpringBoard config", True),
        ("HomeDomain", "Library/Preferences/.GlobalPreferences.plist", "Global preferences", True),
        ("SystemPreferencesDomain", "SystemConfiguration/preferences.plist", "Network configuration", True),
        ("WirelessDomain", "Library/Preferences/com.apple.commcenter.plist", "Cellular/carrier", False),
        ("HomeDomain", "Library/Cookies/Cookies.binarycookies", "Browser cookies", False),
    ]
    
    results = {}
    
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        
        for domain, rel_path, description, is_required in essential_files:
            cursor.execute("""
                SELECT fileID FROM Files 
                WHERE domain = ? AND relativePath = ?
            """, (domain, rel_path))
            row = cursor.fetchone()
            
            filename = rel_path.split("/")[-1]
            
            if not row:
                if is_required:
                    print(f"  ⚠ {filename}: not in backup (expected)")
                else:
                    print(f"  ℹ {filename}: not in backup (optional)")
                results[filename] = {"present": False, "readable": False, "required": is_required}
                continue
            
            file_id = row[0]
            physical_path = backup_dir / file_id[:2] / file_id
            
            if not physical_path.exists():
                print(f"  ⚠ {filename}: in manifest but file missing")
                results[filename] = {"present": False, "readable": False, "required": is_required}
                continue
            
            # Validate file based on type
            readable = False
            if filename.endswith(".plist"):
                try:
                    with open(physical_path, "rb") as f:
                        plistlib.load(f)
                    readable = True
                except Exception:
                    pass
            elif filename.endswith(".sqlite"):
                try:
                    test_conn = sqlite3.connect(str(physical_path))
                    test_cursor = test_conn.cursor()
                    test_cursor.execute("PRAGMA integrity_check")
                    if test_cursor.fetchone()[0] == "ok":
                        readable = True
                    test_conn.close()
                except Exception:
                    pass
            else:
                # For other files (like binarycookies), just verify readable
                try:
                    with open(physical_path, "rb") as f:
                        f.read(1)
                    readable = True
                except Exception:
                    pass
            
            if readable:
                print(f"  ✓ {filename}: present, readable")
            else:
                print(f"  ⚠ {filename}: present but may be corrupt")
            
            results[filename] = {"present": True, "readable": readable, "required": is_required}
        
        # Count KeychainDomain entries
        cursor.execute("""
            SELECT COUNT(*) FROM Files 
            WHERE domain = 'KeychainDomain'
        """)
        keychain_count = cursor.fetchone()[0]
        
        if keychain_count > 0:
            print(f"  ✓ KeychainDomain entries: {keychain_count:,}")
            results["_keychain"] = {"present": True, "count": keychain_count}
        else:
            print("  ⚠ KeychainDomain entries: 0 (unexpected)")
            results["_keychain"] = {"present": False, "count": 0}
        
        conn.close()
        return results
        
    except sqlite3.Error as e:
        print(f"  ✗ Database error: {e}")
        return {}


def full_validation(backup_path: Path, sample_size: int = 100) -> bool:
    """
    Master validation function - runs all checks sequentially.
    
    Runs:
    1. verify_manifest_db - CRITICAL
    2. verify_info_plist - CRITICAL
    3. verify_file_integrity - CRITICAL (any hash error = fail)
    4. verify_critical_system_files - WARNING only
    5. verify_essential_backup_files - WARNING only
    
    Args:
        backup_path: Path to the backup directory
        sample_size: Number of files to sample for integrity check
        
    Returns:
        True if all critical checks pass, False otherwise
    """
    print("")
    print("═" * 65)
    print("                      BACKUP VALIDATION")
    print("═" * 65)
    
    backup_path = Path(backup_path)
    
    # Track results
    results = {
        "manifest_db": False,
        "info_plist": False,
        "file_integrity": False,
        "critical_files": "N/A",
        "essential_files": "N/A",
    }
    
    # Additional tracking
    integrity_stats = (0, 0, 0, [])
    mdm_profiles_present = False
    
    # 1. Verify Manifest.db (CRITICAL)
    results["manifest_db"] = verify_manifest_db(backup_path / "Manifest.db")
    
    # 2. Verify Info.plist (CRITICAL)
    info_data = verify_info_plist(backup_path / "Info.plist")
    results["info_plist"] = info_data is not None
    
    # 3. Verify file integrity (CRITICAL)
    if results["manifest_db"]:
        integrity_stats = verify_file_integrity(backup_path, sample_size)
        validated, missing, errors, error_list = integrity_stats
        # Pass if no hash errors (missing files are just warnings)
        results["file_integrity"] = (errors == 0)
    else:
        print("\n[3/5] Skipping file integrity check (Manifest.db invalid)")
        results["file_integrity"] = False
    
    # 4. Verify critical system files (WARNING)
    if results["manifest_db"]:
        critical_results = verify_critical_system_files(backup_path)
        results["critical_files"] = "OK"
        if critical_results.get("_mdm_profiles", {}).get("present", False):
            results["critical_files"] = "WARN"
            mdm_profiles_present = True
    else:
        print("\n[4/5] Skipping critical files check (Manifest.db invalid)")
    
    # 5. Verify essential backup files (WARNING)
    if results["manifest_db"]:
        essential_results = verify_essential_backup_files(backup_path)
        # Check if any required files are missing
        missing_required = [k for k, v in essential_results.items() 
                          if not k.startswith("_") and v.get("required") and not v.get("present")]
        if missing_required:
            results["essential_files"] = "WARN"
        else:
            results["essential_files"] = "OK"
    else:
        print("\n[5/5] Skipping essential files check (Manifest.db invalid)")
    
    # Print summary
    print("")
    print("═" * 65)
    print("                     VALIDATION SUMMARY")
    print("═" * 65)
    
    # Format results
    def format_status(passed: bool | str) -> str:
        if isinstance(passed, str):
            if passed == "OK":
                return "[PASS]"
            elif passed == "WARN":
                return "[WARN]"
            else:
                return "[N/A]"
        return "[PASS]" if passed else "[FAIL]"
    
    print(f"  Manifest.db           {format_status(results['manifest_db'])}")
    print(f"  Info.plist            {format_status(results['info_plist'])}")
    
    # File integrity with stats
    validated, missing, errors, _ = integrity_stats
    if results["manifest_db"]:
        integrity_detail = f"({validated}/{validated + missing} validated, {missing} missing)"
        print(f"  File Integrity        {format_status(results['file_integrity'])} {integrity_detail}")
    else:
        print(f"  File Integrity        {format_status(results['file_integrity'])}")
    
    # Critical files
    if results["critical_files"] == "WARN":
        print(f"  Critical Files        [WARN] MDM profiles present")
    else:
        print(f"  Critical Files        {format_status(results['critical_files'])}")
    
    print(f"  Essential Files       {format_status(results['essential_files'])}")
    
    print("─" * 65)
    
    # Determine overall result
    critical_passed = all([
        results["manifest_db"],
        results["info_plist"],
        results["file_integrity"]
    ])
    
    if critical_passed:
        print("  Overall Result:       ✓ PASS")
        if mdm_profiles_present:
            print("")
            print("  Note: MDM profiles were detected. This is expected for a backup")
            print("  that has not yet been patched.")
    else:
        print("  Overall Result:       ✗ FAIL")
        print("")
        print("  ⚠ CRITICAL CHECKS FAILED - Do not use this backup for restoration!")
        print("  The backup may be corrupted or incomplete.")
    
    print("═" * 65)
    
    return critical_passed


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Decrypt iOS encrypted backup preserving restore-compatible structure.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -i ~/Backups/encrypted -o /tmp/decrypted
  %(prog)s -i ~/Backups/encrypted -o /tmp/decrypted -p "mypassword"
  %(prog)s -i ~/Backups/encrypted -o /tmp/decrypted -v

Decrypt and validate:
  %(prog)s -i ~/Backups/encrypted -o /tmp/decrypted --validate

Validate existing decrypted backup (no decryption):
  %(prog)s --validate-only /tmp/decrypted
  %(prog)s --validate-only /tmp/decrypted --validation-sample-size 500

Fix encryption metadata in existing decrypted backup:
  %(prog)s --fix-encryption-metadata /tmp/decrypted

After decryption, use with MDMPatcher:
  ./mdm_patch --backup-source /tmp/decrypted
        """
    )
    
    parser.add_argument(
        "-i", "--input",
        type=Path,
        metavar="PATH",
        help="Path to encrypted iOS backup directory"
    )
    
    parser.add_argument(
        "-o", "--output",
        type=Path,
        metavar="PATH",
        help="Output directory for decrypted backup"
    )
    
    parser.add_argument(
        "-p", "--password",
        type=str,
        metavar="PASSWORD",
        help="Backup password (will prompt if not provided)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed progress"
    )
    
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Run validation checks after decryption"
    )
    
    parser.add_argument(
        "--validate-only",
        type=Path,
        metavar="PATH",
        help="Validate an existing decrypted backup (no decryption)"
    )
    
    parser.add_argument(
        "--validation-sample-size",
        type=int,
        default=100,
        metavar="N",
        help="Number of files to check in integrity validation (default: 100)"
    )
    
    parser.add_argument(
        "--fix-encryption-metadata",
        type=Path,
        metavar="PATH",
        help="Fix an existing decrypted backup by correcting Manifest.db metadata"
    )

    parser.add_argument(
        "--skip-metadata-fix",
        action="store_true",
        help="Skip fixing encryption metadata in Manifest.db (not recommended)"
    )

    parser.add_argument(
        "--zero-protection-class",
        action="store_true",
        help="Set ProtectionClass=0 when fixing Manifest.db metadata"
    )
    
    args = parser.parse_args()
    
    # Handle fix-encryption-metadata mode
    if args.fix_encryption_metadata:
        backup_path = Path(args.fix_encryption_metadata)
        if not backup_path.exists():
            print(f"Error: Backup path does not exist: {backup_path}", file=sys.stderr)
            return 1
        if not backup_path.is_dir():
            print(f"Error: Backup path is not a directory: {backup_path}", file=sys.stderr)
            return 1
        
        print(f"Fixing encryption metadata in: {backup_path}")
        print("")
        
        try:
            fix_manifest_db_metadata(
                backup_path,
                zero_protection_class=args.zero_protection_class
            )
            print("")
            print("[+] Done! Backup should now restore without digest errors.")
        except Exception as e:
            print(f"Error: Failed to fix encryption metadata: {e}", file=sys.stderr)
            return 1
        
        return 0
    
    # Handle validate-only mode
    if args.validate_only:
        backup_path = Path(args.validate_only)
        if not backup_path.exists():
            print(f"Error: Backup path does not exist: {backup_path}", file=sys.stderr)
            return 1
        if not backup_path.is_dir():
            print(f"Error: Backup path is not a directory: {backup_path}", file=sys.stderr)
            return 1
        
        validation_passed = full_validation(backup_path, args.validation_sample_size)
        return 0 if validation_passed else 3
    
    # For decryption mode, input and output are required
    if not args.input or not args.output:
        parser.error("the following arguments are required for decryption: -i/--input, -o/--output")
    
    # Validate input
    print("[+] Validating input backup...")
    try:
        validate_input_backup(args.input)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    # Check output doesn't exist
    try:
        setup_output_directory(args.output)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    # Get password
    password = args.password
    if password is None:
        password = getpass.getpass("Backup password: ")
        if not password:
            print("Error: Password cannot be empty", file=sys.stderr)
            # Clean up empty output dir
            shutil.rmtree(args.output)
            return 1
    
    # Load encrypted backup
    print("[+] Loading encrypted backup...")
    print("[+] Deriving decryption keys (this may take a few seconds)...")
    
    try:
        backup = EncryptedBackup(
            backup_directory=str(args.input),
            passphrase=password
        )
    except Exception as e:
        error_msg = str(e).lower()
        if "password" in error_msg or "passphrase" in error_msg or "decrypt" in error_msg:
            print("Error: Incorrect password or corrupted backup", file=sys.stderr)
            # Clean up empty output dir
            shutil.rmtree(args.output)
            return 2
        else:
            print(f"Error: Failed to load backup: {e}", file=sys.stderr)
            shutil.rmtree(args.output)
            return 1
    
    print("[+] Password verified successfully")
    
    # Copy metadata files
    print("[+] Copying metadata files...")
    copy_metadata_files(args.input, args.output)
    
    # Decrypt Manifest.db
    print("[+] Decrypting Manifest.db...")
    try:
        decrypt_manifest_db(backup, args.output)
    except Exception as e:
        print(f"Error: Failed to decrypt Manifest.db: {e}", file=sys.stderr)
        shutil.rmtree(args.output)
        return 1
    
    # Decrypt all backup files
    try:
        decrypt_backup_files(backup, args.input, args.output, verbose=args.verbose)
    except Exception as e:
        print(f"Error: Failed to decrypt backup files: {e}", file=sys.stderr)
        shutil.rmtree(args.output)
        return 1
    
    # Update Manifest.plist to mark as unencrypted
    update_manifest_plist(args.output)
    
    # Strip encryption keys from Manifest.db file metadata
    # This is critical: without this, iOS will try to decrypt already-decrypted files
    if args.skip_metadata_fix:
        print("[*] Skipping Manifest.db metadata fix (--skip-metadata-fix)")
    else:
        try:
            print("[+] Fixing Manifest.db metadata...")
            fix_manifest_db_metadata(
                args.output,
                zero_protection_class=args.zero_protection_class
            )
        except Exception as e:
            print(f"[!] Warning: Failed to fix Manifest.db metadata: {e}", file=sys.stderr)
            print("[!] Restore may fail with 'digest mismatch' errors", file=sys.stderr)
    
    print("")
    print("=" * 50)
    print(f"Backup decrypted successfully to: {args.output}")
    print("")
    print("Use with MDMPatcher:")
    print(f"  ./mdm_patch --backup-source {args.output}")
    print("=" * 50)
    
    # Run validation if requested
    if args.validate:
        validation_passed = full_validation(args.output, args.validation_sample_size)
        if not validation_passed:
            print("")
            print("⚠ Decryption completed but validation FAILED.", file=sys.stderr)
            print("Review the errors above before using this backup.", file=sys.stderr)
            return 3
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

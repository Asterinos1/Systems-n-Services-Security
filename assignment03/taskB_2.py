import os
import hashlib
import shutil
from datetime import datetime

# Function to generate MD5 and SHA256 hashes for a file
def generate_file_hashes(file_path):
    hash_md5 = hashlib.md5()
    hash_sha256 = hashlib.sha256()

    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(2048):  # Read in 2KB chunks
                hash_md5.update(chunk)
                hash_sha256.update(chunk)
        return {
            'md5': hash_md5.hexdigest(),
            'sha256': hash_sha256.hexdigest()
        }
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return None

# Function to load the malware signature database
def load_signature_database(file_path):
    signature_db = []
    try:
        with open(file_path, 'r') as f:
            for line in f.readlines()[2:]:  # Skip header lines
                parts = line.strip().split(" | ")
                if len(parts) == 5:
                    md5_hash, sha256_hash, malware_type, date, severity = parts
                    signature_db.append({
                        'md5': md5_hash,
                        'sha256': sha256_hash,
                        'malware_type': malware_type,
                        'date': date,
                        'severity': severity
                    })
        return signature_db
    except FileNotFoundError:
        print(f"Error: Signature database '{file_path}' not found.")
        return []

# Function to quarantine suspicious files by moving them to a quarantine directory
def quarantine_file(file_path, quarantine_dir, threat_level):
    if not os.path.exists(quarantine_dir):
        os.makedirs(quarantine_dir)
    try:
        quarantine_path = os.path.join(quarantine_dir, os.path.basename(file_path))
        shutil.move(file_path, quarantine_path)
        print(f"File '{file_path}' moved to quarantine ({threat_level} threat).")
    except Exception as e:
        print(f"Error quarantining file '{file_path}': {e}")

# Function to check a file against the malware signature database
def check_file_against_signatures(file_path, signature_db, quarantine_dir, log_file):
    file_hashes = generate_file_hashes(file_path)
    if file_hashes:
        with open(log_file, 'a') as log:
            for entry in signature_db:
                if (file_hashes['md5'] == entry['md5']) or (file_hashes['sha256'] == entry['sha256']):
                    # Log the malware detection
                    log.write(f"{datetime.now()} | {file_path} | MATCH | MD5={file_hashes['md5']}, SHA256={file_hashes['sha256']} | {entry['malware_type']} | {entry['severity']}\n")
                    print(f"Alert: {file_path} is malware! Quarantining...")
                    quarantine_file(file_path, quarantine_dir, entry['severity'])
                    return True
            # If no match found, log as clean
            log.write(f"{datetime.now()} | {file_path} | CLEAN | MD5={file_hashes['md5']}, SHA256={file_hashes['sha256']}\n")
            print(f"{file_path} is clean.")
    return False

# Function to recursively scan a directory for files, compare against malware signatures, and log results
def recursive_scan(directory, signature_db, log_file, quarantine_dir):
    with open(log_file, 'w') as log:  # Start log file with headers
        log.write("Timestamp | File Path | Status | MD5 | SHA256 | Malware Type | Severity\n")
        log.write("-" * 100 + "\n")
    
    for root, dirs, files in os.walk(directory):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            check_file_against_signatures(file_path, signature_db, quarantine_dir, log_file)

# Main function to perform scanning and quarantining
def main():
    directory_to_scan = os.getcwd()  # Change to the directory you want to scan
    signature_file = 'generated_malware_signatures.txt'  # Path to the signature database
    log_file = 'scan_report.log'  # Path to the output log file
    quarantine_dir = 'quarantine'  # Directory where suspicious files will be quarantined

    # Load the signature database
    signature_db = load_signature_database(signature_file)
    
    if not signature_db:
        print("No signatures loaded. Exiting...")
        return

    # Start the recursive scan
    print(f"Starting recursive scan of '{directory_to_scan}'...")
    recursive_scan(directory_to_scan, signature_db, log_file, quarantine_dir)
    print(f"Scan complete. Check the log file '{log_file}' for details.")

if __name__ == "__main__":
    main()

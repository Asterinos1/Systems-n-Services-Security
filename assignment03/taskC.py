import os
import hashlib
import shutil
import time
import argparse
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
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

# Custom event handler for watchdog to monitor file changes
class MalwareFileHandler(FileSystemEventHandler):
    def __init__(self, signature_db, quarantine_dir, log_file):
        self.signature_db = signature_db
        self.quarantine_dir = quarantine_dir
        self.log_file = log_file

    def on_created(self, event):
        if event.is_directory:
            return
        print(f"File created: {event.src_path}")
        check_file_against_signatures(event.src_path, self.signature_db, self.quarantine_dir, self.log_file)

    def on_modified(self, event):
        if event.is_directory:
            return
        print(f"File modified: {event.src_path}")
        check_file_against_signatures(event.src_path, self.signature_db, self.quarantine_dir, self.log_file)

    def on_deleted(self, event):
        if event.is_directory:
            return
        print(f"File deleted: {event.src_path}")
        # Optionally, handle deleted file detection logic here

# Function to start the real-time monitoring
def start_real_time_monitoring(directory, signature_db, log_file, quarantine_dir):
    event_handler = MalwareFileHandler(signature_db, quarantine_dir, log_file)
    observer = Observer()
    observer.schedule(event_handler, path=directory, recursive=True)  # Monitor all subdirectories
    observer.start()
    
    print(f"Real-time monitoring started on {directory}...")
    try:
        while True:
            time.sleep(1)  # Keep the observer running
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# Main function to parse arguments and start the tool
def main():
    parser = argparse.ArgumentParser(description="Real-Time Malware Detection and Monitoring")
    parser.add_argument('-d', '--directory', required=True, help="Directory to scan")
    parser.add_argument('-s', '--signature_file', required=True, help="Path to the malware signature database")
    parser.add_argument('-o', '--output_file', required=True, help="File to save a report of infected files")
    parser.add_argument('-r', '--real_time', action='store_true', help="Run in real-time mode to monitor the directory")

    args = parser.parse_args()

    # Load the signature database
    signature_db = load_signature_database(args.signature_file)

    if not signature_db:
        print("No signatures loaded. Exiting...")
        return

    # If real-time monitoring is enabled
    if args.real_time:
        start_real_time_monitoring(args.directory, signature_db, args.output_file, quarantine_dir="quarantine")

if __name__ == "__main__":
    main()

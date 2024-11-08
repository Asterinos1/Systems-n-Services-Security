import os
import hashlib

# Function to generate multiple hashes for a given file
def generate_file_hashes(file_path):
    hash_md5 = hashlib.md5()
    hash_sha1 = hashlib.sha1()
    hash_sha256 = hashlib.sha256()
    hash_sha512 = hashlib.sha512()

    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(2048):  # Read the file in 8KB chunks
                hash_md5.update(chunk)
                hash_sha1.update(chunk)
                hash_sha256.update(chunk)
                hash_sha512.update(chunk)

        # Return the hexadecimal hashes
        return {
            'md5': hash_md5.hexdigest(),
            'sha1': hash_sha1.hexdigest(),
            'sha256': hash_sha256.hexdigest(),
            'sha512': hash_sha512.hexdigest()
        }
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return None

# Check if file hashes match any in the signature database
def check_file_against_signatures(file_path, signature_db):
    file_hashes = generate_file_hashes(file_path)
    if file_hashes:
        
        print(f"File '{file_path}' hashes: MD5={file_hashes['md5']}, SHA256={file_hashes['sha256']}")
        
        # Now check against the database
        for entry in signature_db:
            #print(f"Signature Hashes: MD5={entry['md5']}, SHA256={entry['sha256']}")
            # Compare MD5 and SHA256 only for malware detection
            if (file_hashes['md5'] == entry['md5']) or (file_hashes['sha256'] == entry['sha256']):
                print(f"Alert: '{file_path}' matches known malware signature.")
                print(f"Details: Type={entry['malware_type']}, Severity={entry['severity']}, Date={entry['date']}")
                return True  # If any match is found, return True (malware detected)
        
        # If no match, print clean message
        print(f"'{file_path}' is clean based on the current signature database.")
    return False  # No match found, return False


# Load signature database from a file
def load_signature_database(file_path):
    signature_db = []
    with open(file_path, 'r') as f:
        for line in f.readlines()[2:]:  # Skip the first two header lines
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

# Main script to scan files
if __name__ == "__main__":
    signature_file = "C:\\Users\\fneon\\Desktop\\Assignment_3\\generated_malware_signatures.txt"  # Path to your signature database file
    signature_db = load_signature_database(signature_file)

    # Directory to scan
    directory = 'test_files'
    for file_name in os.listdir(directory):
        file_path = os.path.join(directory, file_name)
        if os.path.isfile(file_path):
            check_file_against_signatures(file_path, signature_db)




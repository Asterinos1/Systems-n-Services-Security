import hashlib
import random
from datetime import datetime, timedelta

# Load signature database
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

# Function to create random hashes
def random_hashes():
    random_data = str(random.getrandbits(256)).encode('utf-8')
    md5_hash = hashlib.md5(random_data).hexdigest()
    sha256_hash = hashlib.sha256(random_data).hexdigest()
    return md5_hash, sha256_hash

# Function to generate a random severity level
def random_severity():
    return random.choice(['Low', 'Medium', 'High', 'Critical'])

# Function to generate a random malware type or "clean"
def random_malware_type():
    return random.choice(['Virus', 'Worm', 'Ransomware', 'Spyware', 'Adware', 'Clean'])

# Function to generate a random date within the past 2 years
def random_date():
    start_date = datetime.now() - timedelta(days=730)
    random_days = random.randint(0, 730)
    return (start_date + timedelta(days=random_days)).strftime('%Y-%m-%d')

# Create the signature database file
def create_signature_database(file_path, num_entries=50):
    with open(file_path, 'w') as f:
        # Write the header
        f.write("MD5 Hash | SHA256 Hash | Malware Type | Infection Date | Severity Level\n")
        f.write("-" * 85 + "\n")
        
        for _ in range(num_entries):
            md5_hash, sha256_hash = random_hashes()
            malware_type = random_malware_type()
            severity = random_severity() if malware_type != 'Clean' else 'None'
            infection_date = random_date()
            
            # Write the entry
            f.write(f"{md5_hash} | {sha256_hash} | {malware_type} | {infection_date} | {severity}\n")



# Main function to scan files
def main():
    signature_file = "C:\\Users\\fneon\\Desktop\\Assignment_3\\malware_signatures.txt"  
    signature_db = load_signature_database(signature_file)
    print(signature_db)
    #woking

    # Specify the file path
    output_file = 'generated_malware_signatures.txt'
    create_signature_database(output_file)

    print(f"Signature database created: {output_file}")



if __name__ == "__main__":
    main()

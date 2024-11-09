import os
import hashlib

def generate_file_hashes(file_path):
    hash_md5 = hashlib.md5()
    hash_sha1 = hashlib.sha1()
    hash_sha256 = hashlib.sha256()
    hash_sha512 = hashlib.sha512()

    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(2048):
                hash_md5.update(chunk)
                hash_sha1.update(chunk)
                hash_sha256.update(chunk)
                hash_sha512.update(chunk)
        return {
            'md5': hash_md5.hexdigest(),
            'sha1': hash_sha1.hexdigest(),
            'sha256': hash_sha256.hexdigest(),
            'sha512': hash_sha512.hexdigest()
        }
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return None

def check_file_against_signatures(file_path, signature_db):
    file_hashes = generate_file_hashes(file_path)
    if file_hashes:
        
        #print for checking if the hashes of the database are the same as the calculated hashes of the files
        #print(f"File '{file_path}' hashes: MD5={file_hashes['md5']}, SHA256={file_hashes['sha256']}")
        
        #check in database
        for entry in signature_db:
            #compare hashes of database with the calculated hashes of the files
            if (file_hashes['md5'] == entry['md5']) or (file_hashes['sha256'] == entry['sha256']):
                print(f"Alert: '{file_path}' matches known malware signature.")
                print(f"Details: Type={entry['malware_type']}, Severity={entry['severity']}, Date={entry['date']}\n")
                return True
        
        #if there is no match then file is clean
        print(f"'{file_path}' is clean based on the current signature database.\n")
    return False

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

if __name__ == "__main__":
    signature_file = 'generated_malware_signatures.txt'  #allakse to path me to path gia to generated, an kai nomizo doulevei etsi
    #load the malicius signatures
    signature_db = load_signature_database(signature_file)
    


    directory = 'test_files'
    for file_name in os.listdir(directory):
        file_path = os.path.join(directory, file_name)
        if os.path.isfile(file_path):
            check_file_against_signatures(file_path, signature_db)




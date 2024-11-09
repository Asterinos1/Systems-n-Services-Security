import hashlib
import random
import os
from datetime import datetime, timedelta

#function to calculate hashes for a given file
def generate_file_hashes(file_path):
    hash_md5 = hashlib.md5()
    hash_sha256 = hashlib.sha256()

    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(2048):  #read the file in 2KB chunks
                hash_md5.update(chunk)
                hash_sha256.update(chunk)

        #return the hexadecimal hashes
        return {
            'md5': hash_md5.hexdigest(),
            'sha256': hash_sha256.hexdigest()
        }
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return None

#random severity level
def random_severity():
    return random.choice(['Medium', 'High', 'Critical'])

#random malware type
def random_malware_type():
    return random.choice(['Virus', 'Worm', 'Ransomware', 'Spyware', 'Adware'])

#random date of past 2 years
def random_date():
    start_date = datetime.now() - timedelta(days=730)
    random_days = random.randint(0, 730)
    return (start_date + timedelta(days=random_days)).strftime('%Y-%m-%d')

#creates the signature database
def create_signature_database(file_path_output, directory, num_entries=50):
    with open(file_path_output, 'w') as f:
        #this is the header of signature database
        f.write("MD5 Hash | SHA256 Hash | Malware Type | Infection Date | Severity Level\n")
        f.write("-" * 85 + "\n")
        
        #track entries
        entries_written = 0

        #for all the files in the directory
        for file_name in os.listdir(directory):
            if entries_written >= num_entries:
                break  # Stop once we have written enough entries

            #check if the file name is unsafe
            if 'unsafe' not in file_name.lower():
                continue  #skip the files that are not unsafe

            file_path = os.path.join(directory, file_name)
            
            if os.path.isfile(file_path):
                file_hashes = generate_file_hashes(file_path)

                if file_hashes:
                    md5_hash = file_hashes['md5']
                    sha256_hash = file_hashes['sha256']
                    malware_type = random_malware_type()
                    severity = random_severity()
                    infection_date = random_date()

                    #write entry to file
                    f.write(f"{md5_hash} | {sha256_hash} | {malware_type} | {infection_date} | {severity}\n")
                    entries_written += 1


    print(f"Signature database created: {file_path_output}!")

def main():
    output_file = 'generated_malware_signatures.txt'
    directory = 'test_files' #directory of the test files

    #creation of the signature database
    create_signature_database(output_file, directory)

if __name__ == "__main__":
    main()

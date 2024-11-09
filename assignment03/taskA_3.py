import os
import hashlib
from itertools import combinations

def generate_file_hashes(file_path):
    hash_sha1 = hashlib.sha1()
    hash_sha256 = hashlib.sha256()
    hash_sha512 = hashlib.sha512()

    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(2048):  
                hash_sha1.update(chunk)
                hash_sha256.update(chunk)
                hash_sha512.update(chunk)

        return {
            'sha1': hash_sha1.hexdigest(),
            'sha256': hash_sha256.hexdigest(),
            'sha512': hash_sha512.hexdigest()
        }
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return None

if __name__ == "__main__":
    directory = 'sample_pdfs'
    pdf_hashes = []

    #calculate the hashes for each PDF file and store them
    for file_name in os.listdir(directory):
        file_path = os.path.join(directory, file_name)
        if os.path.isfile(file_path) and file_name.endswith('.pdf'):
            file_hashes = generate_file_hashes(file_path)
            if file_hashes:
                pdf_hashes.append((file_name, file_hashes))

    #print(pdf_hashes)
    
    match_found = False

    for (file1, hashes1), (file2, hashes2) in combinations(pdf_hashes, 2):
        sha1_match = hashes1['sha1'] == hashes2['sha1']
        sha256_match = hashes1['sha256'] == hashes2['sha256']
        sha512_match = hashes1['sha512'] == hashes2['sha512']

        if sha1_match or sha256_match or sha512_match:
            match_found = True
            print(f"Match found between '{file1}' and '{file2}':")
            if sha1_match:
                print("  - SHA1 hashes match.")
            if sha256_match:
                print("  - SHA256 hashes match.")
            if sha512_match:
                print("  - SHA512 hashes match.")

    if not match_found:
        print("No matching hashes for PDF files.")

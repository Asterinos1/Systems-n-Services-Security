import os
import hashlib
import random
from fpdf import FPDF

# Function to create a PDF with specific content
def create_pdf(file_path, content):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.multi_cell(0, 10, content)
    pdf.output(file_path)

# Create test PDF files using known content for matching
def create_test_pdfs_with_hashes(signature_db, num_files=10, directory='test_files'):
    os.makedirs(directory, exist_ok=True)
    created_files = []

    for i in range(1, num_files + 1):
        file_path = os.path.join(directory, f'test_file_{i}.pdf')
        if random.random() < 1:  # Create a "malicious" PDF with known content
            malicious_entry = random.choice(signature_db)
            # Use the MD5 as content for simplicity
            content = f"This PDF simulates content with an MD5 hash of {malicious_entry['md5']}."
            print(f"Inserting content with MD5={malicious_entry['md5']} into {file_path}")
            create_pdf(file_path, content)
        else:
            # Generate a PDF with random content
            random_content = " ".join([str(random.randint(0, 1000)) for _ in range(200)])
            create_pdf(file_path, random_content)
        created_files.append(file_path)

    print(f"{num_files} test PDF files created in '{directory}'.")
    return created_files

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

# Main script to create test files
if __name__ == "__main__":
    signature_file = "C:\\Users\\fneon\\Desktop\\Assignment_3\\generated_malware_signatures.txt"  # Path to your signature database file
    signature_db = load_signature_database(signature_file)
    create_test_pdfs_with_hashes(signature_db, num_files=10)

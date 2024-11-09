import os
import hashlib

test_files_dir = "test_files"
os.makedirs(test_files_dir, exist_ok=True)

#function to generate a random file and return its hashes
def generate_random_file(filename, size=1024):
    with open(filename, "wb") as f:
        #write random content
        f.write(os.urandom(size))

for i in range(50):
    file_path = os.path.join(test_files_dir, f"test_file_{i+1}_unsafe.bin")
    generate_random_file(file_path)
for i in range(50):
    file_path = os.path.join(test_files_dir, f"test_file_{51+i}_safe.bin")
    generate_random_file(file_path)

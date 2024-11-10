import os
from taskA_2_create_test_files import generate_random_file
from taskA_1 import create_signature_database
from taskB_1 import generate_random_directories, copy_files_randomly

def setup_environment(test_files_dir, signature_file, base_directory):
    os.makedirs(test_files_dir, exist_ok=True)
    print("Creating test files...")
    for i in range(50):
        file_path = os.path.join(test_files_dir, f"test_file_{i+1}_unsafe.bin")
        generate_random_file(file_path)
    for i in range(50):
        file_path = os.path.join(test_files_dir, f"test_file_{51+i}_safe.bin")
        generate_random_file(file_path)

    print("Generating malware signature database...")
    create_signature_database(signature_file, test_files_dir)

    print("Setting up random directory structure...")
    target_directories = generate_random_directories(base_directory, num_dirs=5, max_depth=3)
    copy_files_randomly(test_files_dir, target_directories)

"""A simple script to setup an enviroment exclusively for our tool."""
if __name__ == "__main__":
    test_files_dir = "test_files"
    signature_file = "generated_malware_signatures.txt"
    base_directory = "random_test_directory"
    
    setup_environment(test_files_dir, signature_file, base_directory)
    print("Setup complete. You can now run the malware detection tool.")

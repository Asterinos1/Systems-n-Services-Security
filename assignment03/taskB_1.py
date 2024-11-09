import os
import random
import shutil

# Function to generate random directory structure
def generate_random_directories(base_dir, num_dirs=3, max_depth=3):
    """Generate random subdirectories up to a given depth."""
    dirs = [base_dir]

    for _ in range(num_dirs):
        current_depth = random.randint(1, max_depth)
        parent_dir = base_dir
        for depth in range(current_depth):
            subdir_name = f"subdir_{depth+1}_{random.randint(1000, 9999)}"
            parent_dir = os.path.join(parent_dir, subdir_name)
            if not os.path.exists(parent_dir):
                os.makedirs(parent_dir)
            dirs.append(parent_dir)

    #print(f"DEBUG: Created {len(dirs)} directories.")
    return dirs

# Function to copy files to random directories
def copy_files_randomly(source_dir, target_dirs):
    """Copy files from source_dir into random directories from target_dirs."""
    files = [f for f in os.listdir(source_dir) if os.path.isfile(os.path.join(source_dir, f))]
    
    if not files:
        #print(f"DEBUG: No files found in source directory: {source_dir}")
        return

    #print(f"DEBUG: Copying {len(files)} files to random directories.")
    
    for file_name in files:
        source_file_path = os.path.join(source_dir, file_name)
        random_target_dir = random.choice(target_dirs)
        target_file_path = os.path.join(random_target_dir, file_name)
        
        # Copy file
        shutil.copy(source_file_path, target_file_path)
        #print(f"DEBUG: Copied file {file_name} to {random_target_dir}")

def main():
    base_directory = os.path.join(os.getcwd(), 'random_test_directory')  # Base directory for random structure
    source_directory = os.path.join(os.getcwd(), 'test_files')  # Directory containing test files

    # Generate random directory structure with subdirectories
    # print(f"DEBUG: Generating random directory structure under {base_directory}")
    target_directories = generate_random_directories(base_directory, num_dirs=5, max_depth=3)

    # Copy files from test_files directory to random subdirectories
    # print(f"DEBUG: Copying files from {source_directory} to the generated directories.")
    copy_files_randomly(source_directory, target_directories)

    # print("DEBUG: File copying complete. You can now run the malware detection script.")

if __name__ == "__main__":
    main()

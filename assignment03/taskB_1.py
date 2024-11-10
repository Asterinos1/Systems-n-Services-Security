import os
import random
import shutil

"""Inside our current directory we generate a new one that has a 'depth' of 3
files maximum and splits to 3 directories each time (like a tree where each node has 3 children)"""
def generate_random_directories(base_dir, num_dirs=3, max_depth=3):
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
    return dirs

"""Take the files from the test_files directory
    and move them inside our test directory. This should create
    a semi realistic enviroment where there are safe and malicious files."""
def copy_files_randomly(source_dir, target_dirs):
    files = [f for f in os.listdir(source_dir) if os.path.isfile(os.path.join(source_dir, f))]
    if not files:
        #in case test_files was not created prior to running the directory generation
        return   
     
    for file_name in files:
        source_file_path = os.path.join(source_dir, file_name)
        random_target_dir = random.choice(target_dirs)
        target_file_path = os.path.join(random_target_dir, file_name)
        shutil.copy(source_file_path, target_file_path)

def main():
    current_directory = os.path.join(os.getcwd(), 'random_test_directory')  
    source_directory = os.path.join(os.getcwd(), 'test_files')  
    print('Generating test directory...')
    target_directories = generate_random_directories(current_directory, num_dirs=5, max_depth=3)
    print('Moving test files inside the test directory...')
    copy_files_randomly(source_directory, target_directories)
    print('Testing enviroment has been setup.')
  

if __name__ == "__main__":
    main()

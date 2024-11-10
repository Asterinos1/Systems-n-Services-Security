import os
import shutil

"""For debugging purposes"""

paths_to_remove = [
    "test_files",
    "random_test_directory",
    "scan_report.log",
    "quarantine",
    "generated_malware_signatures.txt"
]

def remove_path(path):
    if os.path.exists(path):
        if os.path.isdir(path):
            try:
                shutil.rmtree(path)
                print(f"Directory '{path}' has been removed.")
            except Exception as e:
                print(f"Error removing directory '{path}': {e}")
        elif os.path.isfile(path):
            try:
                os.remove(path)
                print(f"File '{path}' has been removed.")
            except Exception as e:
                print(f"Error removing file '{path}': {e}")
    else:
        print(f"'{path}' does not exist.")

def main():
    for path in paths_to_remove:
        remove_path(path)

if __name__ == "__main__":
    main()

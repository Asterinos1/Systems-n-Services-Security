Security of Systems-n-Services (2024-2025)

Assignment03
Students: Asterinos Karalis 2020030107  - Zografoula Ioanna Neamonitaki 2020030088

*** IMPORTANT ***
Make sure to reset and then setup the enviroment before using the tool.
  1) Use 'python reset.py' to reset the generated files (use this for each task.
  2) Use 'setup.py' to setup the enviroment, that is to generate the test_files, the signatures database and the testing directory.

Task A: Signature Database and detection 
  Step 1) Run taskA_2_create_test_files.py 
  Step 2) Run taskA_1.py
  Step 3) Run taskA_2.py
  Step 4) Run taskA_3.py

**Note taskA_3 works right but the pdfs given are all clean so there is not match in the comparison
of the hashes!

Task B: Search and Quarantine  
  Step 1) Run taskA_2_create_test_files.py to create the test_files.
  Step 2) Run taskA_1.py based on test_files to create the signature database.
  Step 3) Run taskB_1.py for directory generation and file movement.
  Step 4) Run taskB_2.py for recursive search and file quarantine.

Task C: Real-Time Monitoring and Anomaly Detection
  ***Make sure to install watchdog lib*** -> pip install watchdog
  Step1) Run setup.py to create the necessary files for Task C.
  Step2) Run taskC_live.py with the correct arguments to monitor a directory LIVE.

  Example usage:
    -python reset.py
    -python setup.py
    -python .\taskC_live.py -d .\random_test_directory\ -s .\generated_malware_signatures.txt -o live.txt 

*** Final tool ***
Don't forget to reset/setup the enviroment.

Real-Time Malware Detection and Monitoring Tool
options:
  -h, --help            show this help message and exit
  -d DIRECTORY, Directory to scan
  -s SIGNATURE_FILE, Path to the malware signature database
  -o OUTPUT_FILE, File to save a report of infected files
  -r, Run in real-time mode to monitor the directory

  Example usage:
    -python.exe .\reset.py
    -python.exe .\setup.py
    (LIVE):
    -python.exe .\malware_detection.py -d .\random_test_directory\ -s .\generated_malware_signatures.txt -o livestuffhere.txt -r
    (INSTANT SCAN):
    -python.exe .\malware_detection.py -d .\random_test_directory\ -s .\generated_malware_signatures.txt -o instantscan.txt

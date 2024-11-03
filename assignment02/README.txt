Security of Systems-n-Services (2024-2025)

Assignment02
Students: Asterinos Karalis 2020030107  - Zografoula Ioanna Neamonitaki 2020030088

Place all files (logger.c, acmonitor.c, test_aclog.c and Makefile) in the same directory, access the directory
through terminal and type in the following order:
1) make
2) LD_PRELOAD=./logger.so ./test_aclog 
This will generate the logging file which can later be accessed by ./acmonitor -(flag)

Options for the acmonitor tool:

-m Prints malicious users
-i <file path> Prints users that modified the file given and the number of modifications
-h Help message

Example usage:
./acmonitor -m
./acmonitor -i /home/user/Desktop/project/file_1  (copy path of file and paste it here basically)

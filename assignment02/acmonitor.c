#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MAX_USERS 10000
#define MAX_FILENAME_LENGTH 256

struct log_entry {
    int uid;
    int access_type;
    int action_denied;
    char date[11];        
    char time[9];        
    char file[MAX_FILENAME_LENGTH];      
    char fingerprint[MAX_FILENAME_LENGTH]; 
};

void list_unauthorized_accesses(FILE *log) {
    struct log_entry entry;
    int unauthorized_count[MAX_USERS] = {0};  // Array to track unauthorized access counts per user ID
    char last_filepath[MAX_USERS][MAX_FILENAME_LENGTH] = {0};  // Last filepath for each user
 
    // Read each line in the log file
    while (fscanf(log, "%d %s %s  %s %d %d %s",
                  &entry.uid,          // User ID
                  entry.file,          //file name
                  entry.date,         
                  entry.time,
                  &entry.access_type,  // (file mode)
                  &entry.action_denied,// Action denied flag
                  entry.fingerprint    
                 )== 7) {
        
        //checking if the fscanf reads right the log file            
        /*        printf("Parsed Entry - UID: %d, File: %s, Date: %s, Time: %s, Access Type: %d, Denied: %d, Hash: %s\n",
               entry.uid, entry.file, entry.date, entry.time, entry.access_type, entry.action_denied, entry.fingerprint);
        */
        
        // check if the access denied flag is 1
        if (entry.action_denied) {
            //check if the last filepath of a spesific user is the current filepath , 
            //if its not then increment the count of the specific user
            if (strcmp(last_filepath[entry.uid], entry.file) != 0) {
                unauthorized_count[entry.uid]++;
                strcpy(last_filepath[entry.uid], entry.file);
            }
            
        }
    }

    // Print user ids with more than 5 unauthorized accesses
    printf("Malicious users:\n");
    for (int i = 0; i < MAX_USERS; i++) {
        if (unauthorized_count[i] > 5) {
            printf("User ID: %d, Unauthorized Attempts: %d\n", i, unauthorized_count[i]);
        }
    }
}


void usage(void) {
    printf(
           "\n"
           "usage:\n"
           "\t./monitor \n"
           "Options:\n"
           "-m, Prints malicious users\n"
           "-i <filename>, Prints table of users that modified "
           "the file <filename> and the number of modifications\n"
           "-h, Help message\n\n"
           );
    exit(1);
}

void list_file_modifications(FILE *log, const char *file_to_scan) {
    struct log_entry entry;
    int modifications[MAX_USERS] = {0};  
    char last_fingerprint[MAX_USERS][MAX_FILENAME_LENGTH] = {0};  // Last fingerprint for each user

    // Read each line in the log file
    while (fscanf(log, "%d %s %s  %s %d %d %s",
                  &entry.uid,         
                  entry.file,         
                  entry.date,         
                  entry.time,
                  &entry.access_type, 
                  &entry.action_denied,
                  entry.fingerprint    
                 )== 7) {

        //checking if the fscanf reads right the log file            
        /*        printf("Parsed Entry - UID: %d, File: %s, Date: %s, Time: %s, Access Type: %d, Denied: %d, Hash: %s\n",
               entry.uid, entry.file, entry.date, entry.time, entry.access_type, entry.action_denied, entry.fingerprint);
        */

        if (strcmp(entry.file, file_to_scan) == 0 && entry.action_denied == 0) {
            //look if the fingerprint is the same as the entry, and if its not then add to the modifications
            if (strcmp(last_fingerprint[entry.uid], entry.fingerprint) != 0) {
                modifications[entry.uid]++;
                strcpy(last_fingerprint[entry.uid], entry.fingerprint);
            }
        }
    }

    printf("File modification for filepath %s:\n", file_to_scan);
    for (int i = 0; i < MAX_USERS; i++) {
        if (modifications[i] > 0) {
            printf("User ID: %d, Modifications: %d\n", i, modifications[i]);
        }
    }
}

int main(int argc, char *argv[]) {
    int ch;
    FILE *log;

    if (argc < 2)
        usage();

    log = fopen("file_logging.log", "r");
    if (log == NULL) {
        printf("Error opening log file \"file_logging.log\"\n");
        return 1;
    }

    while ((ch = getopt(argc, argv, "hi:m")) != -1) {
        switch (ch) {        
        case 'i':
            list_file_modifications(log, optarg);
            break;
        case 'm':
            list_unauthorized_accesses(log);
            break;
        default:
            usage();
        }
    }

    fclose(log);
    return 0;
}



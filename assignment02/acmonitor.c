#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MAX_USERS 10000
#define MAX_FILENAME_LENGTH 256
#define MAX_HASH_LENGTH 256
#define MAX_DATE_LENGTH 30  // Adjust based on the max date string length

struct log_entry {
    int uid;
    int access_type;
    int action_denied;
    char date[20];        // Date string (e.g., "Thu Oct 31")
    char time[9];        // Time string (e.g., "23:45:49")
    char file[256];      // File path
    char fingerprint[256]; // MD5 hash or "0" for no hash
};

void list_unauthorized_accesses(FILE *log) {
    struct log_entry entry;
    int unauthorized_count[MAX_USERS] = {0};  // Array to track unauthorized access counts per user ID
    /*fscanf(log, "%d %s %s  %s %d %d %s",
                  &entry.uid,          // User ID
                  entry.file,         // Date (e.g., "Thu Oct 31")
                  entry.date,         // Time (e.g., "23:45:49")
                  entry.time,
                  &entry.access_type, // Access type (file mode)
                  &entry.action_denied,// Action denied flag
                  entry.fingerprint    // MD5 hash or "0" for no hash
                 );
    printf("Parsed Entry - UID: %d, File: %s, Date: %s,Time: %s, Access Type: %d, Denied: %d, Hash: %s\n",
               entry.uid, entry.file, entry.date, entry.time , entry.access_type, entry.action_denied, entry.fingerprint);
               */
    // Read each line in the log
    while (fscanf(log, "%d %s %s  %s %d %d %s",
                  &entry.uid,          // User ID
                  entry.file,         // Date (e.g., "Thu Oct 31")
                  entry.date,         // Time (e.g., "23:45:49")
                  entry.time,
                  &entry.access_type, // Access type (file mode)
                  &entry.action_denied,// Action denied flag
                  entry.fingerprint    // MD5 hash or "0" for no hash
                 )== 7) {
        
        // Debug print to verify parsing
        printf("Parsed Entry - UID: %d, File: %s, Date: %s, Time: %s, Access Type: %d, Denied: %d, Hash: %s\n",
               entry.uid, entry.file, entry.date, entry.time, entry.access_type, entry.action_denied, entry.fingerprint);
        
        // Check for unauthorized access and count it
        if (entry.action_denied) {
            unauthorized_count[entry.uid]++;
        }
    }

    // Print users with more than 5 unauthorized accesses
    printf("Malicious users with more than 5 unauthorized access attempts:\n");
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
    int modifications[10000] = {0};  // Assuming a max of 10,000 unique user IDs
    char last_fingerprint[10000][256] = {0};  // Last fingerprint for each user

    while (fscanf(log, "%d %s %*s %*s %d %d %s", 
                  &entry.uid, entry.file, 
                  &entry.access_type, &entry.action_denied, 
                  entry.fingerprint) == 5) {

        if (strcmp(entry.file, file_to_scan) == 0 && entry.action_denied == 0) {
            if (strcmp(last_fingerprint[entry.uid], entry.fingerprint) != 0) {
                modifications[entry.uid]++;
                strcpy(last_fingerprint[entry.uid], entry.fingerprint);
            }
        }
    }

    printf("File modification report for %s:\n", file_to_scan);
    for (int i = 0; i < 10000; i++) {
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



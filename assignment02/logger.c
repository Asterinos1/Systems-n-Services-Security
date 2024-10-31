#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/evp.h> // For SHA-256

// Function to compute file hash using SHA-256
void compute_sha256(FILE *file, char *outputBuffer) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        perror("Failed to create EVP_MD_CTX");
        return;
    }
    
    const EVP_MD *md = EVP_sha256();  // Use SHA-256
    EVP_DigestInit_ex(mdctx, md, NULL);
    
    unsigned char buffer[1024];
    size_t bytesRead = 0;
    
    // Read the file and update the hash context
    while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        EVP_DigestUpdate(mdctx, buffer, bytesRead);
    }
    
    // Finalize the hash
    EVP_DigestFinal_ex(mdctx, hash, &lengthOfHash);
    EVP_MD_CTX_free(mdctx);

    // Convert hash to hex string
    for (int i = 0; i < lengthOfHash; i++) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[lengthOfHash * 2] = '\0'; // Null-terminate the hash string
}

// Helper function to log information to the log file
void log_file_access(const char *path, const char *mode, int access_type, int denied) {
    FILE *log_file = fopen("file_logging.log", "a"); 
    printf("Accessing the log file");
    if (!log_file) return;

    // Get UID and current time
    uid_t uid = getuid();
    time_t current_time = time(NULL);
    struct tm *local_time = localtime(&current_time);
    
    // Open the file to hash it
    FILE *file_to_hash = fopen(path, "rb");
    char file_hash[65] = "N/A";
    if (file_to_hash) {
        compute_sha256(file_to_hash, file_hash);
        fclose(file_to_hash);
    }

    // Log the required information
    fprintf(log_file, "UID: %d, File: %s, Date: %02d-%02d-%04d, Time: %02d:%02d:%02d, Access Type: %d, Denied: %d, Hash: %s\n",
            uid, path, local_time->tm_mday, local_time->tm_mon + 1, local_time->tm_year + 1900,
            local_time->tm_hour, local_time->tm_min, local_time->tm_sec, access_type, denied, file_hash);

    fclose(log_file);
}

FILE *fopen(const char *path, const char *mode) {
    // Call the original fopen
    FILE *(*original_fopen)(const char*, const char*) = dlsym(RTLD_NEXT, "fopen");
    FILE *file = original_fopen(path, mode);

    // Check if the file was opened or created
    int access_type = (strchr(mode, 'w') != NULL) ? 0 : 1; // 0 for creation, 1 for open
    int denied = (file == NULL) ? 1 : 0;

    // Log the file access attempt
    log_file_access(path, mode, access_type, denied);

    return file;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    // Call the original fwrite
    size_t (*original_fwrite)(const void*, size_t, size_t, FILE*) = dlsym(RTLD_NEXT, "fwrite");
    size_t result = original_fwrite(ptr, size, nmemb, stream);

    // Get the file descriptor and log the write attempt
    char path[1024];
    int fd = fileno(stream);
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    char actual_path[1024];
    readlink(path, actual_path, sizeof(actual_path) - 1);

    // Log the write operation (access type 2)
    log_file_access(actual_path, "w", 2, 0);

    return result;
}

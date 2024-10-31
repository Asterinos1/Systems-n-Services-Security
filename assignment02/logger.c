#define _GNU_SOURCE
#define LENGTH_SIZE 16

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

#include <openssl/evp.h>

FILE *fopen_direct(const char *path, const char *mode) {
    FILE *original_fopen_ret;
    FILE *(*original_fopen)(const char*, const char*);

    /* Call the original fopen function */
    original_fopen = dlsym(RTLD_NEXT, "fopen");
    original_fopen_ret = (*original_fopen)(path, mode);

    return original_fopen_ret;
}

FILE *fopen(const char *path, const char *mode) {
    /* Check file existence using stat */
    struct stat buffer;
    int exists = (stat(path, &buffer) == 0); // Replaces cfileexists

    FILE *original_fopen_ret;
    FILE *(*original_fopen)(const char*, const char*);

    /* Call the original fopen function */
    original_fopen = dlsym(RTLD_NEXT, "fopen");
    original_fopen_ret = (*original_fopen)(path, mode);

    /* Add your code here */
    char md5_hash[LENGTH_SIZE * 2 + 1];
    int uid = getuid();
    unsigned char *file_name;
    int file_mode, is_action_denied;

    /* Getting the time */
    time_t now = time(&now);
    struct tm *ptm = localtime(&now);
    char datetime[64];
    strftime(datetime, sizeof(datetime), "%Y-%m-%d %H:%M:%S", ptm);

    /* Action is denied until proven the opposite */
    is_action_denied = 1;
    
    file_name = realpath(path, NULL);

    /* Checking fopen Mode and if user has permission for each action */
    if (exists) {
        if (!strcmp(mode, "r") || (!strcmp(mode, "rb"))) {
            file_mode = 2;  // Read mode
            if (access(path, R_OK) == 0)
                is_action_denied = 0;
        } else {
            file_mode = 3;  // Write mode
            if (access(path, W_OK) == 0) {
                is_action_denied = 0;
            }
        }
    } else {
        file_mode = 1;  // Creation mode
        if (access(path, W_OK) == 0)
            is_action_denied = 0;
    }

    /* Generate MD5 hash */
    if ((is_action_denied == 1) || (file_mode == 1)) {
        strcpy(md5_hash, "0");
    } else {
        gen_md5(path, md5_hash);
    }

    /* Log to file */
    FILE *log_ptr = fopen_direct("file_logging.log", "a");
    if (log_ptr != NULL) {
        fprintf(log_ptr, "%d %s %s %d %d %s\n", uid, file_name, datetime, file_mode, is_action_denied, md5_hash);
        fclose(log_ptr);
    }

    return original_fopen_ret;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    size_t original_fwrite_ret;
    size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

    /* Call the original fwrite function */
    original_fwrite = dlsym(RTLD_NEXT, "fwrite");
    original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);

    /* Add your code here */
    char md5_hash[LENGTH_SIZE * 2 + 1];
    int MAXSIZE = 0xFFF;
    char proclnk[0xFFF];
    char path[0xFFF];
    int uid = getuid();
    unsigned char *file_name;
    int fno, file_mode = 3, is_action_denied;
    ssize_t r;

    /* Finding file name from file pointer */
    if (stream != NULL) {
        fno = fileno(stream);
        sprintf(proclnk, "/proc/self/fd/%d", fno);
        r = readlink(proclnk, path, MAXSIZE);
        if (r < 0) {
            printf("failed to readlink\n");
            exit(1);
        }
        path[r] = '\0';
    }
    fflush(stream);
    file_name = basename(path);

    /* Getting the time */
    time_t now = time(&now);
    struct tm *ptm = localtime(&now);
    char datetime[64];
    strftime(datetime, sizeof(datetime), "%Y-%m-%d %H:%M:%S", ptm);

    /* Action is denied until proven the opposite */
    is_action_denied = 1;

    if (access(file_name, W_OK) == 0)
        is_action_denied = 0;

    /* Generate MD5 hash */
    gen_md5(file_name, md5_hash);

    /* Log to file */
    FILE *log_ptr = fopen_direct("file_logging.log", "a");
    if (log_ptr != NULL) {
        fprintf(log_ptr, "%d %s %s %d %d %s\n", uid, path, datetime, file_mode, is_action_denied, md5_hash);
        fclose(log_ptr);
    }

    return original_fwrite_ret;
}

void gen_md5(const char *path, char md5_hash[]) {
    EVP_MD_CTX *mdctx; // Context for the MD5 state
    unsigned char digest[EVP_MD_size(EVP_md5())]; // Buffer for the hash
    FILE *file = fopen_direct(path, "rb"); // Open the file for reading in binary mode
    unsigned char buffer[1024]; // Buffer for reading file
    size_t bytesRead;

    if (file == NULL) {
        perror("File opening failed");
        return; // Handle error opening file
    }

    mdctx = EVP_MD_CTX_new(); // Create new context
    EVP_DigestInit_ex(mdctx, EVP_md5(), NULL); // Initialize the context

    // Read the file in chunks and update the digest
    while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) != 0) {
        EVP_DigestUpdate(mdctx, buffer, bytesRead); // Update the digest with the buffer
    }

    EVP_DigestFinal_ex(mdctx, digest, NULL); // Finalize the digest calculation
    EVP_MD_CTX_free(mdctx); // Free the context

    // Convert the digest to hexadecimal string
    for (int i = 0; i < LENGTH_SIZE; i++) {
        sprintf(&md5_hash[i * 2], "%02X", digest[i]);
    }

    fclose(file); // Close the file
}

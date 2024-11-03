#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

int main() 
{
	int i;
	size_t bytes;
	FILE *file;
	char filenames[10][7] = {"file_0", "file_1", 
			"file_2", "file_3", "file_4",
			"file_5", "file_6", "file_7", 		
			"file_8", "file_9"};
			
	// Test 1: Create dummy files and write to them
	printf("Test 1: Creating and writing to dummy files.\n");
	for (i = 0; i < 10; i++) {
		file = fopen(filenames[i], "w+");  // Create and open for reading/writing
		printf("Accessing file %s\n", filenames[i]);
		if (file == NULL) {
			printf("Error: fopen failed for %s, error: %s\n", filenames[i], strerror(errno));
		} else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			if (bytes > 0)
				printf("Successfully wrote to %s\n", filenames[i]);
			fclose(file);
		}
	}
	printf("Test 1 finished.\n");

	// Test 2: Revoke permissions, attempt access, then restore permissions
	printf("\nTest 2: Revoking permissions, attempting access, and restoring permissions.\n");
	for (i = 0; i < 10; i++) {
		printf("Revoking permissions for %s\n", filenames[i]);
		chmod(filenames[i], 0); // Revoke all permissions
		file = fopen(filenames[i], "r");  // Try to open the file for reading
		if (file == NULL) {
			printf("Error: fopen failed for %s after revoking permissions, error: %s\n", filenames[i], strerror(errno));
		} else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}
		chmod(filenames[i], S_IRWXU); // Restore permissions
		printf("Restored permissions for %s\n", filenames[i]);
	}
	printf("Test 2 finished.\n");

	// Test 3: Revoke permissions, no restoration
	printf("\nTest 3: Revoking permissions without restoring.\n");
	for (i = 0; i < 10; i++) {
		chmod(filenames[i], 0); // Revoke permissions
		file = fopen(filenames[i], "a");  // Try to append
		if (file == NULL) {
			printf("Error: fopen failed for %s in append mode, error: %s\n", filenames[i], strerror(errno));
		} else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}
		// No permission restoration in this test
	}
	printf("Test 3 finished.\n");

	// Test 4: Attempt to read and write to files with different modes
	printf("\nTest 4: Accessing files in various modes (r, w, a).\n");
	for (i = 0; i < 10; i++) {
		// Try to read the file
		file = fopen(filenames[i], "r");
		if (file == NULL) {
			printf("Error: fopen failed for %s in read mode, error: %s\n", filenames[i], strerror(errno));
		} else {
			printf("Successfully opened %s in read mode.\n", filenames[i]);
			fclose(file);
		}
		
		// Try to open for writing
		file = fopen(filenames[i], "w");
		if (file == NULL) {
			printf("Error: fopen failed for %s in write mode, error: %s\n", filenames[i], strerror(errno));
		} else {
			printf("Successfully opened %s in write mode.\n", filenames[i]);
			fclose(file);
		}
		
		// Try to open for appending
		file = fopen(filenames[i], "a");
		if (file == NULL) {
			printf("Error: fopen failed for %s in append mode, error: %s\n", filenames[i], strerror(errno));
		} else {
			printf("Successfully opened %s in append mode.\n", filenames[i]);
			fclose(file);
		}
	}
	printf("Test 4 finished.\n");
	
	return 0;
}

#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>

int main() 
{
	int i;
	size_t bytes;
	FILE *file;
	char filenames[10][7] = {"file_0", "file_1", 
			"file_2", "file_3", "file_4",
			"file_5", "file_6", "file_7", 		
			"file_8", "file_9"};

	printf("1st loop.\n");
	printf("Creating some dummy files.\n");
	for (i = 0; i < 10; i++) {
		file = fopen(filenames[i], "w+");
		printf("Accessing file %s\n", filenames[i]);
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}

	}
	printf("1st loop finished\n");

	printf("2nd loop.\n");
	printf("Revoking permissions.\n");
	printf("Attempting modifications and then returning permissions.\n");
	for (i = 0; i < 10; i++) {
		chmod(filenames[i], 0); // Revoke permissions
		file = fopen(filenames[i], "r");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}
		chmod(filenames[i], S_IRWXU); // Return permissions
	}
	printf("2nd loop finished\n");

	printf("3rd loop.\n");
	printf("Revoking permissions but no restoring them after.\n");
	for (i = 0; i < 10; i++) {
		// chmod(filenames[i], 0); // Revoke permissions
		file = fopen(filenames[i], "a");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}
		// chmod(filenames[i], S_IRWXU); // Return permissions
	}
	printf("3rd loop finished\n");
}

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sodium.h>
#include <string.h>
#include <time.h>

//Elliptic Curve Diffie-Hellman (ECDH) Key Exchange

// setting key size.
#define KEY_SIZE 32 

// display the help message
void print_help() {
    printf("Command Line Options for ECDH Tool:\n");
    printf("\t-o path      Path to output file\n");
    printf("\t-a number    Alice's private key (optional)\n");
    printf("\t-b number    Bob's private key (optional)\n");
    printf("\t-h           This help message\n");
}

// Function to write keys and shared secret to the output file
void create_file(const char *filename, const unsigned char *alice_pub, const unsigned char *bob_pub,
                  const unsigned char *shared_secret) {
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        perror("Error opening file");
        exit(1);
    }

    fprintf(file, "Alice's Public Key:\n");
    for (int i = 0; i < KEY_SIZE; i++) {
        fprintf(file, "%02x", alice_pub[i]);
    }
    fprintf(file, "\n");

    fprintf(file, "Bob's Public Key:\n");
    for (int i = 0; i < KEY_SIZE; i++) {
        fprintf(file, "%02x", bob_pub[i]);
    }
    fprintf(file, "\n");

    fprintf(file, "Shared Secret (Alice):\n");
    for (int i = 0; i < KEY_SIZE; i++) {
        fprintf(file, "%02x", shared_secret[i]);
    }
    fprintf(file, "\n");

    fprintf(file, "Shared Secret (Bob):\n");
    for (int i = 0; i < KEY_SIZE; i++) {
        fprintf(file, "%02x", shared_secret[i]);
    }
    fprintf(file, "\n");
    fprintf(file, "Shared secrets match!");

    fclose(file);

    printf("Keys and shared secret were succesfully written to '%s'\n", filename);
}

int main(int argc, char *argv[]) {
    int opt;
    char *output_file = NULL;

    unsigned char alice_private[KEY_SIZE];
    unsigned char bob_private[KEY_SIZE];
    unsigned char alice_public[KEY_SIZE];
    unsigned char bob_public[KEY_SIZE];
    unsigned char shared_secret[KEY_SIZE];

    // For debugging purposes.
    // Initialising the sodium lib.
    if (sodium_init() < 0) {
        printf("Failed to initialize libsodium.\n");
        return 1;
    }else{
        printf("\n**DEBUG**\nLibsodium initialised.\n");
    }

    // Parsing command-line arguments using getopt
    while ((opt = getopt(argc, argv, "o:a:b:h")) != -1) {
        switch (opt) {
            case 'o':
                output_file = optarg;  // Path to the output file
                break;
            case 'a':
                //set Alice's private key if provided
                if (sscanf(optarg, "%32hhx", alice_private) != 1) {
                    printf("Invalid input for Alice's private key.\n");
                    return 1;
                }
                break;
            case 'b':
                //set Bob's private key if provided
                if (sscanf(optarg, "%32hhx", bob_private) != 1) {
                    printf("Invalid input for Bob's private key.\n");
                    return 1;
                }
                break;
            case 'h':
                print_help();
                return 0;  // Exit after showing the help message
            default:
                print_help();
                return 1;  // Invalid option, show help and exit with error
        }
    }

    // Check if the output file is provided
    if (output_file == NULL) {
        fprintf(stderr, "Error: Output file is required.\n");
        print_help();
        return 1;
    }

    // For Debugging
    // Print the private keys:
    // printf(alice_private);
    // printf(bob_private);

    //generate Alice's private key randomly if not provided.
    if (alice_private[0] == 0) {
        randombytes_buf(alice_private, sizeof(alice_private));
    }

    //generate Bob's private key randomly if not provided.
    if (bob_private[0] == 0) {
        randombytes_buf(bob_private, sizeof(bob_private));
    }

    //generate public keys 
    crypto_scalarmult_base(alice_public, alice_private); // alice_public = alice_private * G
    crypto_scalarmult_base(bob_public, bob_private);    // bob_public = bob_private * G

    //calculate shared secrets
	unsigned char alice_shared_secret[KEY_SIZE];
	unsigned char bob_shared_secret[KEY_SIZE];

    // For Debugging purposes.
	// calculate Alice's shared secret
	if (crypto_scalarmult(alice_shared_secret, alice_private, bob_public) != 0) {
		printf("Failed to calculate Alice's shared secret.\n");
		return 1;
	}
	// calculate Bob's shared secret
	if (crypto_scalarmult(bob_shared_secret, bob_private, alice_public) != 0) {
		printf("Failed to calculate Bob's shared secret.\n");
		return 1;
	}

    // verify that shared secrets match
    // using memcmp since we're dealing with unsigned char data type.
    if (memcmp(alice_shared_secret, bob_shared_secret, KEY_SIZE) != 0) {
        printf("Error: Shared secrets do not match!\n");
        return 1;
    }

    // write keys and shared secret to the output file
    create_file(output_file, alice_public, bob_public, alice_shared_secret);

    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>  // Add this for strcmp and atoi
#include <gmp.h>
#include <sys/time.h> // For get_time_in_seconds

// RSA Key Pair Generation
void generateRSAKeyPair(int key_length) {
    mpz_t p, q, n, lambda_n, e, d, gcd;
    gmp_randstate_t state;

    // Initialize GMP integers
    mpz_inits(p, q, n, lambda_n, e, d, gcd, NULL);
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    // Generate two large prime numbers p and q
    int half_key_length = key_length / 2;
    mpz_urandomb(p, state, half_key_length);
    mpz_urandomb(q, state, half_key_length);
    mpz_nextprime(p, p); // Find next prime greater than p
    mpz_nextprime(q, q); // Find next prime greater than q

    // Compute n = p * q
    mpz_mul(n, p, q);

    // Compute lambda(n) = lcm(p-1, q-1)
    mpz_t p_minus_1, q_minus_1;
    mpz_inits(p_minus_1, q_minus_1, NULL);
    mpz_sub_ui(p_minus_1, p, 1);
    mpz_sub_ui(q_minus_1, q, 1);
    mpz_lcm(lambda_n, p_minus_1, q_minus_1);

    // Choose e such that 1 < e < lambda(n) and gcd(e, lambda(n)) = 1
    mpz_set_ui(e, 65537); // Commonly used value of e
    mpz_gcd(gcd, e, lambda_n);
    while (mpz_cmp_ui(gcd, 1) != 0) {
        mpz_add_ui(e, e, 2); // Increment e until gcd(e, lambda_n) = 1
        mpz_gcd(gcd, e, lambda_n);
    }

    // Compute d, the modular inverse of e mod lambda(n)
    mpz_invert(d, e, lambda_n);

    // Output the key pair (n, e) is public, (n, d) is private
    gmp_printf("Public key: \n n: %Zd\n e: %Zd\n", n, e);
    gmp_printf("Private key: \n n: %Zd\n d: %Zd\n", n, d);

    // Clear memory
    mpz_clears(p, q, n, lambda_n, e, d, gcd, p_minus_1, q_minus_1, NULL);
    gmp_randclear(state);
}

// RSA Encryption
void rsa_encrypt(const char* input_file, const char* output_file, const char* pub_key_file) {
    mpz_t n, e, plaintext, ciphertext;
    mpz_inits(n, e, plaintext, ciphertext, NULL);

    // Read public key (n, e) from file
    FILE *pub_key = fopen(pub_key_file, "r");
    gmp_fscanf(pub_key, "%Zd %Zd", n, e);
    fclose(pub_key);

    // Read plaintext from input file
    FILE *input = fopen(input_file, "r");
    gmp_fscanf(input, "%Zd", plaintext);
    fclose(input);

    // Encrypt: ciphertext = plaintext^e mod n
    mpz_powm(ciphertext, plaintext, e, n);

    // Write ciphertext to output file
    FILE *output = fopen(output_file, "w");
    gmp_fprintf(output, "%Zd", ciphertext);
    fclose(output);

    // Clear memory
    mpz_clears(n, e, plaintext, ciphertext, NULL);
}

// RSA Decryption
void rsa_decrypt(const char* input_file, const char* output_file, const char* priv_key_file) {
    mpz_t n, d, plaintext, ciphertext;
    mpz_inits(n, d, plaintext, ciphertext, NULL);

    // Read private key (n, d) from file
    FILE *priv_key = fopen(priv_key_file, "r");
    gmp_fscanf(priv_key, "%Zd %Zd", n, d);
    fclose(priv_key);

    // Read ciphertext from input file
    FILE *input = fopen(input_file, "r");
    gmp_fscanf(input, "%Zd", ciphertext);
    fclose(input);

    // Decrypt: plaintext = ciphertext^d mod n
    mpz_powm(plaintext, ciphertext, d, n);

    // Write plaintext to output file
    FILE *output = fopen(output_file, "w");
    gmp_fprintf(output, "%Zd", plaintext);
    fclose(output);

    // Clear memory
    mpz_clears(n, d, plaintext, ciphertext, NULL);
}

// Helper function to get the current time in seconds
double get_time_in_seconds() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec / 1e6;
}

// Performance Analysis
void compare_performance(const char* input_file) {
    int key_lengths[] = {1024, 2048, 4096};
    for (int i = 0; i < 3; i++) {
        int key_length = key_lengths[i];

        // Generate key pair
        generateRSAKeyPair(key_length);

        // Measure encryption time
        double start = get_time_in_seconds();
        rsa_encrypt(input_file, "ciphertext.txt", "public.key");
        double encryption_time = get_time_in_seconds() - start;

        // Measure decryption time
        start = get_time_in_seconds();
        rsa_decrypt("ciphertext.txt", "plaintext.txt", "private.key");
        double decryption_time = get_time_in_seconds() - start;

        // Output results
        printf("Key Length: %d bits\n", key_length);
        printf("Encryption Time: %.4f seconds\n", encryption_time);
        printf("Decryption Time: %.4f seconds\n", decryption_time);
    }
}

// Main function
int main(int argc, char *argv[]) {
    int key_length = 0;
    char *input_file = NULL, *output_file = NULL, *key_file = NULL;
    int generate = 0, encrypt = 0, decrypt = 0, analyze = 0;

    // Argument parsing
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-g") == 0) {
            if (i + 1 < argc) {
                key_length = atoi(argv[++i]);
                generate = 1;
            } else {
                fprintf(stderr, "Error: Missing key length after -g\n");
                return 1;
            }
        } else if (strcmp(argv[i], "-i") == 0) {
            if (i + 1 < argc) {
                input_file = argv[++i];
            } else {
                fprintf(stderr, "Error: Missing input file after -i\n");
                return 1;
            }
        } else if (strcmp(argv[i], "-o") == 0) {
            if (i + 1 < argc) {
                output_file = argv[++i];
            } else {
                fprintf(stderr, "Error: Missing output file after -o\n");
                return 1;
            }
        } else if (strcmp(argv[i], "-k") == 0) {
            if (i + 1 < argc) {
                key_file = argv[++i];
            } else {
                fprintf(stderr, "Error: Missing key file after -k\n");
                return 1;
            }
        } else if (strcmp(argv[i], "-e") == 0) {
            encrypt = 1;
        } else if (strcmp(argv[i], "-d") == 0) {
            decrypt = 1;
        } else if (strcmp(argv[i], "-a") == 0) {
            analyze = 1;
        } else if (strcmp(argv[i], "-h") == 0) {
            printf("Usage: ./rsa_assign_1 -g [key_length] | -i [input_file] -o [output_file] -k [key_file] -e | -d | -a\n");
            return 0;
        } else {
            fprintf(stderr, "Error: Unknown option %s\n", argv[i]);
            return 1;
        }
    }
}
    // Ensure required arguments are provided for encrypt and decrypt
   

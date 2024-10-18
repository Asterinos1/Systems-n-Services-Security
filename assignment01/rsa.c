#include <stdio.h>
#include <gmp.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

void generatePrime(int length, mpz_t p, mpz_t q){
    gmp_printf("Primes: \n 1: %Zd\n 2: %Zd\n", p, q);
    printf("Length/2: %d\n", length );

    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));
    mpz_urandomb(p, state, length);
    mpz_urandomb(q, state, length);
    mpz_nextprime(p, p); // Find next prime greater than p
    mpz_nextprime(q, q); // Find next prime greater than q
    

    if(!(mpz_probab_prime_p(p,1000)>0 && (mpz_probab_prime_p(q,1000)>0))){
        generatePrime(length,p,q);
    }
    gmp_printf("Primes after: \n 1: %Zd\n 2: %Zd\n", p, q);

    gmp_randclear(state);
}


void generateRSAKeyPair(int key_length, mpz_t p, mpz_t q) {
    gmp_printf("Primes after generateRSAKeyPair: \n 1: %Zd\n 2: %Zd\n", p, q);
    mpz_t n, lambda_n, e, d, gcd;
    gmp_randstate_t state;

    // Initialize GMP integers
    mpz_init(n);
    mpz_init(lambda_n);
    mpz_init(e);
    mpz_init(d);
    mpz_init(gcd);

    // Compute n = p * q
    mpz_mul(n, p, q);

    // Compute lambda(n) = lcm(p-1, q-1)
    mpz_t p_minus_1, q_minus_1;
    mpz_init(p_minus_1);
    mpz_init(q_minus_1);

    mpz_sub_ui(p_minus_1, p, 1);
    mpz_sub_ui(q_minus_1, q, 1);
    mpz_mul(lambda_n, p_minus_1, q_minus_1);

    mpz_t reminder;
    mpz_init(reminder);
    mpz_set_ui(e,2);

    do
    {   
        mpz_mod(reminder,e,lambda_n);
        mpz_gcd(gcd,e,lambda_n);
        if(mpz_probab_prime_p(e,20)>0 && mpz_cmp_d(reminder,0) !=0 && mpz_cmp_d(gcd,1) == 0) {
            break;
        }
        mpz_add_ui(e,e,1);
    } while (1);
    
    // Compute d, the modular inverse of e mod lambda(n)
    mpz_invert(d, e, lambda_n);

    // Output the key pair (n, e) is public, (n, d) is private
    gmp_printf("Public key: \n n: %Zd\n d: %Zd\n", n, d);
    gmp_printf("Private key: \n n: %Zd\n e: %Zd\n", n, e);

    FILE *pub_key_file = fopen("public.key", "w");
    FILE *priv_key_file = fopen("private.key", "w");
    gmp_fprintf(pub_key_file, "%Zd %Zd", n, d);
    gmp_fprintf(priv_key_file, "%Zd %Zd", n, e);

    fclose(pub_key_file);
    fclose(priv_key_file);


    // Clear memory
    mpz_clears(n, lambda_n, e, d, gcd, p_minus_1, q_minus_1, NULL);
    mpz_clear(reminder);
}

void print_help() {
   printf("RSA Different key length Tool\n\n"
                "Options:\n"
                "-i path Path to the input file\n"
                "-o path Path to the output file\n"
                "-k path Path to the key file\n"
                "-g length Perform RSA key-pair generation given a key length “length”\n"
                "-d Decrypt input and store results to output.\n"
                "-e Encrypt input and store results to output.\n"
                "-a Compare the performance of RSA encryption and decryption with three\n"
                "   different key lengths (1024, 2048, 4096 key lengths) in terms of computational time.\n"
                "-h This help message\n\n");
}

int main(int argc, char *argv[]) {
    int key_length = 0;
    char *input_file = NULL, *output_file = NULL, *key_file = NULL;
    int generate = 0, encrypt = 0, decrypt = 0, analyze = 0;

    // Argument parsing loop
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0) {
            print_help();
            return 0;
        }
        else if (strcmp(argv[i], "-g") == 0) {
            if (i + 1 < argc) {
                key_length = atoi(argv[++i]);
                generate = 1;
            } else {
                fprintf(stderr, "Error: Missing key length after -g\n");
                return 1;
            }
        } 
        else if (strcmp(argv[i], "-i") == 0) {
            if (i + 1 < argc) {
                input_file = argv[++i];
            } else {
                fprintf(stderr, "Error: Missing input file after -i\n");
                return 1;
            }
        } 
        else if (strcmp(argv[i], "-o") == 0) {
            if (i + 1 < argc) {
                output_file = argv[++i];
            } else {
                fprintf(stderr, "Error: Missing output file after -o\n");
                return 1;
            }
        } 
        else if (strcmp(argv[i], "-k") == 0) {
            if (i + 1 < argc) {
                key_file = argv[++i];
            } else {
                fprintf(stderr, "Error: Missing key file after -k\n");
                return 1;
            }
        } 
        else if (strcmp(argv[i], "-e") == 0) {
            encrypt = 1;
        } 
        else if (strcmp(argv[i], "-d") == 0) {
            decrypt = 1;
        } 
        else if (strcmp(argv[i], "-a") == 0) {
            analyze = 1;
        } 
        else {
            fprintf(stderr, "Error: Unknown option %s\n", argv[i]);
            return 1;
        }
    }

    // Perform actions based on flags
    if (generate) {
        printf("Generating RSA keys of length %d...\n", key_length);
        // Your RSA key generation logic here
        mpz_t p; 
        mpz_init(p);
        mpz_t q;
        mpz_init(q);

        generatePrime(key_length/2, p, q);
        generateRSAKeyPair(key_length, p,q);

    } 
    else if (encrypt) {
        printf("Encrypting input file %s using key file %s...\n", input_file, key_file);
        // Your encryption logic here
    } 
    else if (decrypt) {
        printf("Decrypting input file %s using key file %s...\n", input_file, key_file);
        // Your decryption logic here
    } 
    else if (analyze) {
        printf("Analyzing RSA performance...\n");
        // Your analysis logic here
    }

    return 0;
}

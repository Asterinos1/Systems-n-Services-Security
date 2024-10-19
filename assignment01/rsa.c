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

    /*Initiliazation*/
    mpz_init(n);
    mpz_init(lambda_n);
    mpz_init(e);
    mpz_init(d);
    mpz_init(gcd);

    mpz_mul(n, p, q);  //n = p * q

    mpz_t p_minus_1, q_minus_1;
    mpz_init(p_minus_1);
    mpz_init(q_minus_1);

    mpz_sub_ui(p_minus_1, p, 1); //(p-1)
    mpz_sub_ui(q_minus_1, q, 1); //(q-1)
    mpz_mul(lambda_n, p_minus_1, q_minus_1); //(p-1)*(q-1)

    mpz_t reminder;
    mpz_init(reminder);
    mpz_set_ui(e,65537); //e=65537 (to diabasa se ena site)

    //find a suitable e
    do
    {   
        mpz_mod(reminder,e,lambda_n);
        mpz_gcd(gcd,e,lambda_n);
        if(mpz_probab_prime_p(e,1000)>0 && mpz_cmp_d(reminder,0) !=0 && mpz_cmp_d(gcd,1) == 0) {
            break;
        }
        mpz_add_ui(e,e,1);
    } while (1);

    //find d 
    mpz_invert(d, e, lambda_n);

    //testing delete later
    gmp_printf("Public key: \n n: %Zd\n d: %Zd\n", n, e);
    gmp_printf("Private key: \n n: %Zd\n e: %Zd\n", n, d);

    //write public and private key to the files
    FILE *pub_key_file = fopen("public.key", "w");
    FILE *priv_key_file = fopen("private.key", "w");
    gmp_fprintf(pub_key_file, "%Zd %Zd", n, e);
    gmp_fprintf(priv_key_file, "%Zd %Zd", n, d);

    //close files
    fclose(pub_key_file);
    fclose(priv_key_file);


    // Clear memory
    mpz_clears(n, lambda_n, e, d, gcd, p_minus_1, q_minus_1, NULL);
    mpz_clear(reminder);
}


void rsa_encrypt(const char* input_file, const char* output_file, const char* pub_key_file) {
    mpz_t n, e, plaintext, ciphertext;
    mpz_inits(n, e, plaintext, ciphertext, NULL);

    //read public key from file
    FILE *pub_key = fopen(pub_key_file, "r");
    gmp_fscanf(pub_key, "%Zd %Zd", n, e);
    fclose(pub_key);

    //read plaintext from input file
    FILE *input = fopen(input_file, "r");
    gmp_fscanf(input, "%Zd", plaintext);
    fclose(input);

    mpz_powm(ciphertext, plaintext, e, n); //ciphertext = plaintext^e mod n

    FILE *output = fopen(output_file, "w");
    gmp_fprintf(output, "%Zd", ciphertext);
    fclose(output);

    mpz_clears(n, e, plaintext, ciphertext, NULL);
}


void rsa_decrypt(const char* input_file, const char* output_file, const char* priv_key_file) {
    mpz_t n, d, plaintext, ciphertext;
    mpz_inits(n, d, plaintext, ciphertext, NULL);


    FILE *priv_key = fopen(priv_key_file, "r");
    gmp_fscanf(priv_key, "%Zd %Zd", n, d);
    fclose(priv_key);

    FILE *input = fopen(input_file, "r");
    gmp_fscanf(input, "%Zd", ciphertext);
    fclose(input);

    
    mpz_powm(plaintext, ciphertext, d, n); //plaintext = ciphertext^d mod n

    FILE *output = fopen(output_file, "w");
    gmp_fprintf(output, "%Zd", plaintext);
    fclose(output);

    // Clear memory
    mpz_clears(n, d, plaintext, ciphertext, NULL);
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

    if (generate) {
        printf("Generating RSA keys of length %d...\n", key_length);
        mpz_t p; 
        mpz_init(p);
        mpz_t q;
        mpz_init(q);

        generatePrime(key_length/2, p, q);
        generateRSAKeyPair(key_length, p,q);

    } 
    else if (encrypt) {
        printf("Encrypting input file %s using key file %s...\n", input_file, key_file);
        rsa_encrypt(input_file,output_file, key_file);
    } 
    else if (decrypt) {
        printf("Decrypting input file %s using key file %s...\n", input_file, key_file);
        rsa_decrypt(input_file,output_file,key_file);
    } 
    else if (analyze) {
        printf("Analyzing RSA performance...\n");
        //auto menei akoma
    }



    return 0;
}

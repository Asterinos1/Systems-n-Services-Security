#include <stdio.h>
#include <gmp.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#define SIZE_OF_CIPHER_BYTE 256

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
    gmp_printf("Public key: \n n: %Zd\n e: %Zd\n", n, e);
    gmp_printf("Private key: \n n: %Zd\n d: %Zd\n", n, d);

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
    mpz_t n, e, plaintext, gmp_letter, cipherletter;
    mpz_inits(n, e, plaintext,cipherletter,gmp_letter, NULL);
    long *temp =  (long*) malloc(SIZE_OF_CIPHER_BYTE); 
    
    //read public key from file
    FILE *pub_key = fopen(pub_key_file, "r");
    

    gmp_fscanf(pub_key, "%Zd %Zd", n, e);
    fclose(pub_key);

    FILE *input = fopen(input_file, "r");
    FILE *output = fopen(output_file, "w");

    int letter;
    while ((letter=fgetc(input)) != EOF) { 
            mpz_set_ui(gmp_letter, letter);
            mpz_powm(cipherletter, gmp_letter, e, n); 

            mpz_export(temp, NULL, 0, SIZE_OF_CIPHER_BYTE, 0, 0, cipherletter);
            fwrite(temp, SIZE_OF_CIPHER_BYTE, 1, output);
        }

    fclose(input);

    fclose(output);

    mpz_clears(n, e, plaintext, gmp_letter, cipherletter, NULL);
    free(temp);
}


void rsa_decrypt(char *infile_name, char *outfile_name, char *keyfile_name){
        FILE *keyfile = fopen(keyfile_name, "r");
        mpz_t n, d;
        mpz_init(n);
        mpz_init(d);
        gmp_fscanf(keyfile, "%Zd %Zd", n, d);
        
        mpz_t plain_text, desypher_text;
        mpz_init(plain_text);
        mpz_init(desypher_text);
        long *temp =  (long*) malloc(SIZE_OF_CIPHER_BYTE);
        int *c = (int*) malloc(sizeof(int));  

        FILE *input = fopen(infile_name, "r");
        FILE *output = fopen(outfile_name, "w");

        while (fread(temp, SIZE_OF_CIPHER_BYTE, 1, input) != 0) {

            mpz_import (plain_text, 1, 0, SIZE_OF_CIPHER_BYTE, 0, 0, temp);
            mpz_powm(desypher_text, plain_text, d, n); 

            mpz_export(c, NULL, 0, sizeof(int), 0, 0, desypher_text);
            fputc((char)*c, output);
        }

        mpz_clears(n, d, plain_text, desypher_text, NULL);
        fclose(input);
        fclose(output);
        fclose(keyfile);
        free(c);
        free(temp);

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
        rsa_decrypt(input_file,output_file, key_file);

    } 
    else if (analyze) {
        printf("Analyzing RSA performance...\n");
        mpz_t p1024; 
        mpz_init(p1024);
        mpz_t q1024;
        mpz_init(q1024);

        mpz_t p2048; 
        mpz_init(p2048);
        mpz_t q2048;
        mpz_init(q2048);

        mpz_t p4096; 
        mpz_init(p4096);
        mpz_t q4096;
        mpz_init(q4096);
        /*
        generatePrime(1024/2, p1024, q1024);
        generateRSAKeyPairForPerformance(1024, p1024, q1024, "public_1024.key", "private_1024.key");

        generatePrime(2048/2, p2048, q2048);
        generateRSAKeyPairForPerformance(2048, p2048, q2048, "public_2048.key", "private_2048.key");

        generatePrime(4096/2, p4096, q4096);
        generateRSAKeyPairForPerformance(4096, p4096, q4096, "public_4096.key", "private_4096.key");

        double start_encrypt_1024 = get_time_in_seconds();
        rsa_encrypt(input_file, "outputperfomance.txt", "public_1024.key");
        double encryption_time1024 = get_time_in_seconds() - start_encrypt_1024;

        double start_decrypt_1024 = get_time_in_seconds();
        rsa_decrypt("outputperfomance.txt", "performance.txt", "private_1024.key");
        double decryption_time1024 = get_time_in_seconds() - start_decrypt_1024;

        double start_encrypt_2048 = get_time_in_seconds();
        rsa_encrypt(input_file, "outputperfomance.txt", "public_2048.key");
        double encryption_time2048 = get_time_in_seconds() - start_encrypt_2048;

        double start_decrypt_2048 = get_time_in_seconds();
        rsa_decrypt("outputperfomance.txt", "performance.txt", "private_2048.key");
        double decryption_time_2048 = get_time_in_seconds() - start_decrypt_2048;

        double start_encrypt_4096= get_time_in_seconds();
        rsa_encrypt(input_file, "outputperfomance.txt", "public_2048.key");
        double encryption_time_4096 = get_time_in_seconds() - start_encrypt_4096;

        double start_decrypt_4096 = get_time_in_seconds();
        rsa_decrypt("outputperfomance.txt", "performance.txt", "private_4096.key");
        double decryption_time_4096 = get_time_in_seconds() - start_decrypt_4096;
*/
    }



    return 0;
}

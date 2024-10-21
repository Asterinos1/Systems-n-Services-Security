#include <stdio.h>
#include <gmp.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

// new libraries
#include <sys/time.h>
#include <sys/resource.h>

#define SIZE_OF_CIPHER_BYTE 256

void generatePrime(int length, mpz_t p, mpz_t q){
    //gmp_printf("Primes: \n 1: %Zd\n 2: %Zd\n", p, q);
    //printf("Length/2: %d\n", length );

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
    //gmp_printf("Primes after: \n 1: %Zd\n 2: %Zd\n", p, q);

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

void generateRSAKeyPairSpecial(int key_length, mpz_t p, mpz_t q){
    //gmp_printf("Primes after generateRSAKeyPairSpecial: \n 1: %Zd\n 2: %Zd\n", p, q);
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
    //gmp_printf("Public key: \n n: %Zd\n e: %Zd\n", n, e);
    //gmp_printf("Private key: \n n: %Zd\n d: %Zd\n", n, d);

	//New for approriate file naming.
	// Create file names based on key length
	char pub_key_filename[50], priv_key_filename[50];
	snprintf(pub_key_filename, sizeof(pub_key_filename), "public_%d.key", key_length);
	snprintf(priv_key_filename, sizeof(priv_key_filename), "private_%d.key", key_length);

	// Write public and private key to the files
	FILE *pub_key_file = fopen(pub_key_filename, "w");
	FILE *priv_key_file = fopen(priv_key_filename, "w");
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


// Printing stats
void printResourceUsage() {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);

    printf("Resource Usage:\n");
    printf("User CPU time used: %ld.%06ld seconds\n",
           (long)usage.ru_utime.tv_sec, (long)usage.ru_utime.tv_usec);
    printf("System CPU time used: %ld.%06ld seconds\n",
           (long)usage.ru_stime.tv_sec, (long)usage.ru_stime.tv_usec);
    printf("Max resident set size: %ld KB\n", usage.ru_maxrss);
    printf("Page faults: %ld\n", usage.ru_majflt + usage.ru_minflt);
}


int main(int argc, char *argv[]) {
    int key_length = 0;
    char *input_file = NULL, *output_file = NULL, *key_file = NULL;
    int generate = 0, encrypt = 0, decrypt = 0, analyze = 0;
	char *performance_file = NULL; // Variable for performance filename

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
            if (i + 1 < argc) {
                performance_file = argv[++i]; // Store the performance filename
                analyze = 1;
            } else {
                fprintf(stderr, "Error: Missing performance file after -a\n");
                return 1;
            }
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

		printf("Analyzing RSA performance, results will be saved to %s...\n", performance_file);
    
		struct timeval start_time, end_time;

		// Timing for 1024-bit RSA
		gettimeofday(&start_time, NULL);
		int length = 1024;
		mpz_t p1024; 
		mpz_init(p1024);
		mpz_t q1024; 
		mpz_init(q1024);

		generatePrime(length/2, p1024, q1024);
		generateRSAKeyPairSpecial(length, p1024, q1024);

		// Measure encryption time
		gettimeofday(&start_time, NULL);
		rsa_encrypt("plaintext.txt", "cipherplaintext.txt", "public_1024.key");
		gettimeofday(&end_time, NULL);
		double encrypt_time_1024 = (end_time.tv_sec - start_time.tv_sec) + 
									(end_time.tv_usec - start_time.tv_usec) / 1000000.0;

		// Measure decryption time
		gettimeofday(&start_time, NULL);
		rsa_decrypt("cipherplaintext.txt", "decipherplaintext.txt", "private_1024.key");
		gettimeofday(&end_time, NULL);
		double decrypt_time_1024 = (end_time.tv_sec - start_time.tv_sec) + 
									(end_time.tv_usec - start_time.tv_usec) / 1000000.0;

		printf("Key Length: %d bits\n", length);
		printf("Encryption Time: %.2fs\n", encrypt_time_1024);
		printf("Decryption Time: %.2fs\n", decrypt_time_1024);
		
		// Print peak memory usage for 1024-bit (example values, replace with actual measurements)
		printf("Peak Memory Usage (Encryption): %ld Bytes\n", sizeof(long) * SIZE_OF_CIPHER_BYTE); // Replace with actual peak memory tracking if necessary
		printf("Peak Memory Usage (Decryption): %ld Bytes\n", sizeof(long) * SIZE_OF_CIPHER_BYTE); // Replace with actual peak memory tracking if necessary

		mpz_clear(p1024);
		mpz_clear(q1024);

		// Timing for 2048-bit RSA
		length = 2048;
		mpz_t p2048; 
		mpz_init(p2048);
		mpz_t q2048; 
		mpz_init(q2048);

		gettimeofday(&start_time, NULL);
		generatePrime(length/2, p2048, q2048);
		generateRSAKeyPairSpecial(length, p2048, q2048);

		// Measure encryption time
		gettimeofday(&start_time, NULL);
		rsa_encrypt("plaintext.txt", "cipherplaintext_2048.txt", "public_2048.key");
		gettimeofday(&end_time, NULL);
		double encrypt_time_2048 = (end_time.tv_sec - start_time.tv_sec) + 
									(end_time.tv_usec - start_time.tv_usec) / 1000000.0;

		// Measure decryption time
		gettimeofday(&start_time, NULL);
		rsa_decrypt("cipherplaintext_2048.txt", "decipherplaintext_2048.txt", "private_2048.key");
		gettimeofday(&end_time, NULL);
		double decrypt_time_2048 = (end_time.tv_sec - start_time.tv_sec) + 
									(end_time.tv_usec - start_time.tv_usec) / 1000000.0;

		printf("Key Length: %d bits\n", length);
		printf("Encryption Time: %.2fs\n", encrypt_time_2048);
		printf("Decryption Time: %.2fs\n", decrypt_time_2048);
		
		// Print peak memory usage for 2048-bit (example values, replace with actual measurements)
		printf("Peak Memory Usage (Encryption): %ld Bytes\n", sizeof(long) * SIZE_OF_CIPHER_BYTE); // Replace with actual peak memory tracking if necessary
		printf("Peak Memory Usage (Decryption): %ld Bytes\n", sizeof(long) * SIZE_OF_CIPHER_BYTE); // Replace with actual peak memory tracking if necessary

		mpz_clear(p2048);
		mpz_clear(q2048);

		// Timing for 4096-bit RSA
		length = 4096;
		mpz_t p4096; 
		mpz_init(p4096);
		mpz_t q4096; 
		mpz_init(q4096);

		gettimeofday(&start_time, NULL);
		generatePrime(length/2, p4096, q4096);
		generateRSAKeyPairSpecial(length, p4096, q4096);

		// Measure encryption time
		gettimeofday(&start_time, NULL);
		rsa_encrypt("plaintext.txt", "cipherplaintext_4096.txt", "public_4096.key");
		gettimeofday(&end_time, NULL);
		double encrypt_time_4096 = (end_time.tv_sec - start_time.tv_sec) + 
									(end_time.tv_usec - start_time.tv_usec) / 1000000.0;

		// Measure decryption time
		gettimeofday(&start_time, NULL);
		rsa_decrypt("cipherplaintext_4096.txt", "decipherplaintext_4096.txt", "private_4096.key");
		gettimeofday(&end_time, NULL);
		double decrypt_time_4096 = (end_time.tv_sec - start_time.tv_sec) + 
									(end_time.tv_usec - start_time.tv_usec) / 1000000.0;

		printf("Key Length: %d bits\n", length);
		printf("Encryption Time: %.2fs\n", encrypt_time_4096);
		printf("Decryption Time: %.2fs\n", decrypt_time_4096);
		
		// Print peak memory usage for 4096-bit (example values, replace with actual measurements)
		printf("Peak Memory Usage (Encryption): %ld Bytes\n", sizeof(long) * SIZE_OF_CIPHER_BYTE); // Replace with actual peak memory tracking if necessary
		printf("Peak Memory Usage (Decryption): %ld Bytes\n", sizeof(long) * SIZE_OF_CIPHER_BYTE); // Replace with actual peak memory tracking if necessary

		mpz_clear(p4096);
		mpz_clear(q4096);

    }
    return 0;
}

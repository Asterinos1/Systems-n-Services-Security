#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define SIZE_OF_CIPHER_BYTE 256


/**
 * Arithmetic calculation of parameter e 
 * 
 */
void calculate_e(mpz_t e, mpz_t lambda);
/**
 * Checks the length of an mpz variable
 * Used to check if p and q lengths are key length/2
 */
void check_bit_length(mpz_t num, int expected_length);
/**
 * Generates the 2 keys given p and q ad writs them in separate public.key and private.key files
 * 
 * @param num
 * @param length
 * 
 */
void generateRSAKeypair(mpz_t gmp_p, mpz_t gmp_q);
/**
 * 
 * Generates two prime number p and q with certain length given
 */
void generate_prime_pair(int key_length, mpz_t p, mpz_t q);
/**
 * 
 * Performs encryption of the plain text given in the input file using a key and stores the cipher text in the output file
 * @param infile_name 
 * @param outfile_name 
 * @param keyfile_name 
 */
void performEncryption(char *infile_name, char *outfile_name, char *keyfile_name);
/**
 * @ Performs decryption of the cipher text in the input file given a key and stores the plaintext in the output file
 * 
 * @param infile_name 
 * @param outfile_name 
 * @param keyfile_name 
 */
void performDecryption(char *infile_name, char *outfile_name, char *keyfile_name);
/*
Options:
    -i path Path to the input file
    -o path Path to the output file
    -k path Path to the key file
    -l length Length of the key    
    -g Perform RSA key-pair generation
    -d Decrypt input and store results to output
    -e Encrypt input and store results to output
    -h This help message
    -a Compare The Perfomance of RSA Encryption and Decryption
*/

int main(int argc, char *argv[]){

    char *outfile_name=NULL, *infile_name=NULL, *keyfile_name=NULL, *keylength= NULL, *performancefile_name= NULL, *decryptedfile_name= NULL;
    int key_length= -1;
    int mode = -1;  // -1 is error, 0 is generate, 1 is encrypt, 2 is decrypt

    //Help message
    const char *help_message = "Options:\n\t-i path Path to the input file\n\t-o path Path to the output file\n\t-k path Path to the key file\n\t-l length Length of the key\n\t-g Perform RSA key-pair generation\n\t-d Decrypt input and store results to output\n\t-e Encrypt input and store results to output\n\t-p path Path to the perfomance file\n\t-h This help message";

    //used in switch
    int opt; 

    // Options via a getopt switch
    // parse command line arguments
    while ((opt = getopt(argc, argv, "p:l:i:o:k:gdeha")) != -1) {
        switch (opt) {
            case 'i':
                infile_name = optarg;
                break;
            case 'l':
                keylength= optarg;
                break;
            case 'o':
                outfile_name = optarg;
                break;
            case 'k':
                keyfile_name = optarg;
                break;
            case 'g':
                mode = 0;
                break;
            case 'a':
                mode = 3;
                break;
            case 'p':
                performancefile_name= optarg;
                break;
            case 'e':
                mode = 1;
                break;
            case 'd':
                mode = 2;
                break;
            case 'h':
                printf("%s\n", help_message);
                exit(0);
            default:
                printf("Invalid option. Use option -h for help.\n");
                exit(-1);
        }
    }

    // if after parsing arguments any of the filenames is NULL, an argument was missing
    if (mode == 1 || mode == 2) {
        if (outfile_name == NULL) {
            printf("Cannot proceed without an output file path! Please provide one. Use the -h option for help.\n");
            exit(-1);
        }
        
        if (infile_name == NULL) {
            printf("Cannot proceed without an input file path! Please provide one. Use the -h option for help.\n");
            exit(-1);
        }
        
        if (keyfile_name == NULL) {
            printf("Cannot proceed without a key file path! Please provide one. Use the -h option for help.\n");
            exit(-1);
        }
    }
    if (mode == 0){
        if(keylength== NULL){
            printf("Cannot proceed without a key length! Please provide one. Use the -h option for help.\n");
            exit(-1);
        }
    }
    if (mode == 3){
        if(performancefile_name== NULL){
            printf("Cannot proceed without perfomance file path! Please provide one. Use the -h option for help.\n");
            exit(-1);
        }
        if (infile_name == NULL) {
            printf("Cannot proceed without an input file path! Please provide one. Use the -h option for help.\n");
            exit(-1);
        }
        if (outfile_name == NULL) {
            printf("Cannot proceed without an output file path! Please provide one. Use the -h option for help.\n");
            exit(-1);
        }
    }
    
    // do things
    if (mode == 0) {        // key generation

        // initialize the key length as a int
        key_length= atoi(keylength);


        int p, q;

        // read p and q from the command line
        printf("You have selected the key generation mode.\n");
        printf("You need to insert 2 prime numbers (p and q) and a key length\n");

        // Get p and q values
        mpz_t gmp_p, gmp_q;
        mpz_init(gmp_p);
        mpz_init(gmp_q);

        // Ask for p
        printf("Enter p: ");
        // Read p as gmp variable
        gmp_scanf("%Zd", gmp_p);

        // Ask for q
        printf("Enter q: ");
        // Read q as gmp variable
        gmp_scanf("%Zd", gmp_q);


        //first check if p and q are keylength/2
        check_bit_length(gmp_p,key_length);
        check_bit_length(gmp_q,key_length);
     
        // test if p and q are prime
        int p_is_prime = mpz_probab_prime_p(gmp_p, 33);
        int q_is_prime = mpz_probab_prime_p(gmp_q, 33);
        

        //if not terminate the program
        if (p_is_prime == 0) {
            printf("p (%d) is not prime. Please enter a prime number. Use option -h for help.\n", p_is_prime);
            exit(-1);
        }
        if (q_is_prime == 0) {
            printf("q (%d) is not prime. Please enter a prime number. Use option -h for help.\n", q_is_prime);
            exit(-1);
        }
        //generate the keys and store them in public.key and private.key files
        generateRSAKeypair(gmp_p,gmp_q);
        mpz_clear(gmp_p);
        mpz_clear(gmp_q);
        

    } else if (mode == 1) {  
        // Do the encryption
        performEncryption(infile_name, outfile_name, keyfile_name);
       

    } else if (mode == 2){   
        // Do the decryption
        performDecryption(infile_name, outfile_name, keyfile_name);
        
        
    }
    // Check the Performance of RCA Encryption and Decryption with 3 pairs of keys with key lengths 1024 2048 4096
    else if (mode == 3){

        //open the performance file
        FILE *performance_file = fopen(performancefile_name, "w");
        if (performance_file == NULL) {
            printf("Something has gone wrong while opening the performance file.\n");
            exit(-1);
        }

        
        
        int key_lengths[] = {1024, 2048, 4096};

        // keep count of the total times
        double total_encryption_time,total_decryption_time;
       
        for (int i = 0; i < 3; i++) {
            //for each key length do the rsa 
            int key_length = key_lengths[i];
            mpz_t gmp_p, gmp_q;
            mpz_init(gmp_p);
            mpz_init(gmp_q);

            //generate p,q and create the 2 keys
            generate_prime_pair(key_length, gmp_p, gmp_q);
            generateRSAKeypair(gmp_p, gmp_q);
    

            fprintf(performance_file, "Key Length: %d bits\n", key_length);

            struct timespec first_start, first_end,second_start,second_end;
            double first_elapsed_time, second_elapsed_time;

            // Record the starting time
            clock_gettime(CLOCK_MONOTONIC, &first_start); 

            performEncryption(infile_name,outfile_name,"private.key");

            // Record the ending time
            clock_gettime(CLOCK_MONOTONIC, &first_end); 

            // Calculate time passed for encryption
            first_elapsed_time = (first_end.tv_sec - first_start.tv_sec) + (first_end.tv_nsec - first_start.tv_nsec) / 1e9;
            
            // Write down the results
            fprintf(performance_file, "Encryption Time: %f seconds\n", first_elapsed_time);
            
            //keep track of total encryption time
            total_encryption_time+= first_elapsed_time;

            //now measure time for decryption

            // Record the starting time
            clock_gettime(CLOCK_MONOTONIC, &second_start); 

            performDecryption(outfile_name,"decrypted.txt","public.key");
            
            // Record the ending time
            clock_gettime(CLOCK_MONOTONIC, &second_end); 
            
            // Calculate time passed for decryption
            second_elapsed_time = (second_end.tv_sec - second_start.tv_sec) + (second_end.tv_nsec - second_start.tv_nsec) / 1e9;

            // Write down the results
            fprintf(performance_file, "Decryption Time: %f seconds\n\n", second_elapsed_time);

            //keep track of total decryption time
            total_decryption_time+= second_elapsed_time;

            //clear
            mpz_clear(gmp_p);
            mpz_clear(gmp_q);
            

        }
        //Write down Total results
        fprintf(performance_file, "Total Encryption Time: %f seconds , Total Decryption Time: %f seconds\n", total_encryption_time,total_decryption_time);
        double decryption_encryption= total_decryption_time / total_encryption_time;
        fprintf(performance_file, "Total_Decryption/Total_Encryption: %f",decryption_encryption);
        fclose(performance_file);
    }
    

}


void calculate_e(mpz_t e, mpz_t lambda){

    mpz_t one, mod, gcd;
    mpz_init(mod);
    mpz_init(gcd);
    mpz_set_ui(e, 2);
    mpz_init_set_ui(one, 1);

    while(1){

        mpz_mod(mod, e, lambda);
        mpz_gcd(gcd, e, lambda);
        if (mpz_cmp(mod, one)!=0 && mpz_cmp(gcd, one)==0) {
            break;
        }
        mpz_add_ui(e, e, 1);
        //mpz_nextprime(e,e);
    }

    mpz_clear(one);
    mpz_clear(mod);
    mpz_clear(gcd);
}

// Function to check if mpz_t has the expected number of bits
void check_bit_length(mpz_t num, int expected_length) {
    int bit_length = mpz_sizeinbase(num, 2);
    int length= expected_length/2;
    if (bit_length != length){
        printf(" Number length  is not keylength/2 , please provide n,p with a length of keylength/2 \n");
        exit (-1);
    }
}

void generateRSAKeypair(mpz_t gmp_p, mpz_t gmp_q){
    
    // since both p and q are prime, we can conitnue
    // calculate n 
    mpz_t gmp_n;
    mpz_init(gmp_n);
    //calculate lambda(n)
    mpz_mul(gmp_n, gmp_p, gmp_q);
    mpz_t lambda_n, gmp_one;
    mpz_init(lambda_n);
    mpz_init_set_ui(gmp_one, 1);
    mpz_sub(gmp_p, gmp_p, gmp_one);   
    mpz_sub(gmp_q, gmp_q, gmp_one);  
    mpz_mul(lambda_n, gmp_p, gmp_q);      // lambda(n) = (p-1) * (q-1) (Euler's totient function)
    // choose e (e is required to be prime and also < lambda)
    mpz_t gmp_e;
    mpz_init(gmp_e);
    calculate_e(gmp_e, lambda_n);
    // calculate d, where d is the modular inverse of e and lambda_n
    mpz_t gmp_d;
    mpz_init(gmp_d);
    mpz_invert(gmp_d, gmp_e, lambda_n);
    // math over, store results in files
    FILE *pub_key_file = fopen("public.key", "w");
    FILE *priv_key_file = fopen("private.key", "w");
    gmp_fprintf(pub_key_file, "%Zd %Zd", gmp_n, gmp_d);
    gmp_fprintf(priv_key_file, "%Zd %Zd", gmp_n, gmp_e);
    // clean up and exit
    mpz_clear(gmp_d);
    mpz_clear(gmp_e);
    mpz_clear(lambda_n);
    mpz_clear(gmp_one);
    mpz_clear(gmp_n);
    fclose(pub_key_file);
    fclose(priv_key_file);
}

void generate_prime_pair(int key_length, mpz_t gmp_p, mpz_t gmp_q) {
    gmp_randstate_t state;
    gmp_randinit_default(state);

    // Set the seed for the random number generator (you can customize this)
    unsigned long seed = time(NULL);
    gmp_randseed_ui(state, seed);

    // Set the number of Miller-Rabin tests (higher values are more secure)
    int num_tests = 33;

    int prime_bits = key_length / 2;
    
    while (1) {
        // Generate random prime candidates p and q
        mpz_urandomb(gmp_p, state, prime_bits);
        // Ensure the most significant bit is set
        mpz_setbit(gmp_p, prime_bits - 1);  
        mpz_nextprime(gmp_p, gmp_p);
        
        mpz_urandomb(gmp_q, state, prime_bits);
        // Ensure the most significant bit is set
        mpz_setbit(gmp_q, prime_bits - 1);  
        mpz_nextprime(gmp_q, gmp_q);

        // Check if p and q are different
        if (mpz_cmp(gmp_p, gmp_q) != 0) {
            // Check primality using Miller-Rabin
            if (mpz_probab_prime_p(gmp_p, num_tests) && mpz_probab_prime_p(gmp_q, num_tests)) {
                break;  // Both p and q are prime
            }
        }
    }

    gmp_randclear(state);
}

void performEncryption(char *infile_name, char *outfile_name, char *keyfile_name){
    // get the key (n, e) from the file and import it to GMP
        
        int e, n;
        FILE *keyfile = fopen(keyfile_name, "r");
        mpz_t gmp_e, gmp_n;
        mpz_init(gmp_e);
        mpz_init(gmp_n);
        gmp_fscanf(keyfile, "%Zd %Zd", gmp_n, gmp_e);

        // prepare to iterate through the file
        mpz_t gmp_m, gmp_res;
        mpz_init(gmp_m);
        mpz_init(gmp_res);
        long *tmp =  (long*) malloc(SIZE_OF_CIPHER_BYTE); // variable to store the cipher of each byte.
        int m;  // the cursor
        FILE *infile = fopen(infile_name, "r");
        FILE *outfile = fopen(outfile_name, "w");

        if (outfile==NULL || infile==NULL) {
            printf("Something has gone wrong while opening the files.\n");
            exit(-1);
        }

        // iterate throught the characters of the file
        while ((m=fgetc(infile)) != EOF) { 
            // import the letter to GMP and calculate the cipher
            mpz_set_ui(gmp_m, m);
            mpz_powm(gmp_res, gmp_m, gmp_e, gmp_n); // m^e mod n

            // export the result to a primitive and write it to the file
            mpz_export(tmp, NULL, 0, SIZE_OF_CIPHER_BYTE, 0, 0, gmp_res);
            fwrite(tmp, SIZE_OF_CIPHER_BYTE, 1, outfile);
        }
        
        // clean up and exit
        mpz_clear(gmp_e);
        mpz_clear(gmp_n);
        mpz_clear(gmp_m);
        mpz_clear(gmp_res);
        fclose(infile);
        fclose(outfile);
        fclose(keyfile);
        free(tmp);
        //printf("executes\n");
}

void performDecryption(char *infile_name, char *outfile_name, char *keyfile_name){
    // get the key (n, d) from the file and import it to GMP
        int d, n;
        FILE *keyfile = fopen(keyfile_name, "r");
        mpz_t gmp_d, gmp_n;
        mpz_init(gmp_d);
        mpz_init(gmp_n);
        gmp_fscanf(keyfile, "%Zd %Zd", gmp_n, gmp_d);

        // prepare to iterate through the file
        mpz_t gmp_c, gmp_res;
        mpz_init(gmp_c);
        mpz_init(gmp_res);
        long *tmp =  (long*) malloc(SIZE_OF_CIPHER_BYTE); // variable to store the cipher of each byte.
        int *c = (int*) malloc(sizeof(int));    // the deciphered cursor
        FILE *infile = fopen(infile_name, "r");
        FILE *outfile = fopen(outfile_name, "w");

        // iterate through the file 
        while (fread(tmp, SIZE_OF_CIPHER_BYTE, 1, infile) != 0) {

            // import the bytes to GMP and decipher it
            mpz_import (gmp_c, 1, 0, SIZE_OF_CIPHER_BYTE, 0, 0, tmp);
            mpz_powm(gmp_res, gmp_c, gmp_d, gmp_n); // c^d mod n

            // export the deciphered character to a primitive and write it to the file
            mpz_export(c, NULL, 0, sizeof(int), 0, 0, gmp_res);
            fputc((char)*c, outfile);
        }

        mpz_clear(gmp_d);
        mpz_clear(gmp_n);
        mpz_clear(gmp_c);
        mpz_clear(gmp_res);
        fclose(infile);
        fclose(outfile);
        fclose(keyfile);
        free(c);
        free(tmp);

}

Security of Systems-n-Services (2024-2025)

Assignment01
Students: Asterinos Karalis 2020030107
		  Zografoula Ioanna Neamonitaki 202030088

Run 'make' in the terminal to generate both tools rsa_assign_1 and ecdh_assign_1.

Part1:

	Elliptic Curve Diffie-Hellman (ECDH) Key Exchange

	For the creation of our tool we based our work on this page https://libsodium.gitbook.io/doc/advanced/scalar_multiplication
	of the libsodium's documentation.

	At first we initialize the libsodium library and then we expect one of the following commands to be 
	inserted by the user:

	Command Line Options for ECDH Tool:
		-o path Path to output file
		-a number Alice's private key (optional)
		-b number Bob's private key (optional)
		-h This help message
		
	Example usage: ./ecdh_assign_1 -o "output.txt" -a 10 -b 20 (parameters -a/-b are optional)

	If Alice's/Bob's keys are not provided then we generate them using randombytes_buf() which is provided
	libsodium and generates random bytes.

	Then using crypto_scalarmult_base() of libsodium we calculate the public key by multiplying 
	the private key with 'G' of the elliptic curve.
	
	After we calculate the shared secret key using crypto_scalarmult() of libsodium and check using memcmp
	to see that we get the same shared key.
	
	Finaly we use create_file() to create the file in which we store the data (the generated keys as well as the shared key)
	
Part2:

	RSA Algorithm
	
	The user can select the following operations when running the rsa tool.
	
	RSA Options:
		-i path Path to the input file
		-o path Path to the output file
		-k path Path to the key file
		-g length Perform RSA key-pair generation given a key length “length”
		-d Decrypt input and store results to output.
		-e Encrypt input and store results to output.
		-a Compare the performance of RSA encryption and decryption with three
		different key lengths (1024, 2048, 4096 key lengths) in terms of computational time.
		-h This help message
	
	First you have to generate keys with a given length './rsa_assign_1 -g 1024'
	
	Then specify input/output files with -i/-o accordignly.
	
	Finaly select between -e (encryption) or -d (decryption) for example
	'./rsa_assign_1 -e -i "plaintext.txt" -o "en_output.txt" -k "public.key"
	This will encrypt plaintext.txt and the ciphered text will be saved in en_output.txt
	To decipher, do type './rsa_assign_1 -d -i "en_output.txt" -o "de_output.txt" -k "private.key"
	
	If cipher is done using public key, use private to decipher and vice versa.
	
		For generation of keys (-g) we declare mpz_t variables of the GMP library and initialize them with mpz_init.
	Then, we create a state for random number generation and we initialize it with the seed being the local time.
	Then using we random numbers with mpz_urandomb() and get the next prime of them using mpz_nextprime()
	Then we check if both numbers are prime with the if statement and finaly clear the state.
	
		Then we can proceed to key generation with using the prime numbers and following the steps of the algorithm.
	We initialize the necessary variables and proceed with the correspodning operations (mpz_mul, mpz_sub_ui)
	We set e to 65537. Keys are stored in public.key and private.key files (-g).
	
		Encryption/Decryption functions work similary. First we check the files for the keys and then  perform
	the mod operation to encrypt/decrypt (mpz_mod).
	
		Regarding the performance operation (-a) there was a modification done to the original key generation function
	that stores the keys accroding to their length.
	
	

/*
 * This file contains the parameters for the Kyber algorithm.
 * Think of these parameters as the "settings" or "rules" for our secret message exchange.
 * These parameters define the size of keys, how much we can encrypt, and how secure it is.
 */
#ifndef PARAMS_H
#define PARAMS_H

/*
 * KYBER_K is the security level parameter. You can think of it as a difficulty setting.
 * A higher 'K' means stronger security, but it also means our keys and messages will be a bit bigger.
 * It's like having a longer password to make it harder to guess.
 *
 * KYBER_K = 2 corresponds to Kyber-512 (similar security to AES-128)
 * KYBER_K = 3 corresponds to Kyber-768 (similar security to AES-192)
 * KYBER_K = 4 corresponds to Kyber-1024 (similar security to AES-256)
 *
 * We set it to 3 by default if it's not already defined.
 */
#ifndef KYBER_K
#define KYBER_K 3	/* Change this for different security strengths */
#endif


/*
 * This part of the code creates a unique name for all the functions depending on the security level 'K'.
 * It's like giving a unique jersey number to players of different teams (Kyber-512, Kyber-768, Kyber-1024)
 * so we don't get them mixed up if we use them in the same program.
 * The '##' is a special trick in C to join text together to make a new name.
 */
/* Don't change parameters below this line */
#if   (KYBER_K == 2)
#define KYBER_NAMESPACE(s) pqcrystals_kyber512_ref_##s
#elif (KYBER_K == 3)
#define KYBER_NAMESPACE(s) pqcrystals_kyber768_ref_##s
#elif (KYBER_K == 4)
#define KYBER_NAMESPACE(s) pqcrystals_kyber1024_ref_##s
#else
#error "KYBER_K must be in {2,3,4}"
#endif

/*
 * KYBER_N and KYBER_Q are the core mathematical constants for Kyber.
 * Kyber is based on math with polynomials (expressions like 3x^2 + 5x - 2).
 *
 * KYBER_N = 256: This is the maximum degree of the polynomials we use.
 * KYBER_Q = 3329: This is a special prime number. All our calculations with polynomial coefficients
 *                 are done "modulo Q", which means we only care about the remainder when we divide by 3329.
 *                 This keeps the numbers from getting too big.
 */
#define KYBER_N 256
#define KYBER_Q 3329

/*
 * KYBER_SYMBYTES is the size in bytes for our seeds and hash outputs.
 * A "seed" is a small random number that we can use to generate much larger amounts of random-looking data.
 * A "hash" is like a digital fingerprint of some data.
 * We use 32 bytes, which is the output size of the SHA-256 hash function, a very common standard.
 */
#define KYBER_SYMBYTES 32   /* size in bytes of hashes, and seeds */

/*
 * KYBER_SSBYTES is the size of the "shared secret".
 * This is the final key that two people will agree on after running the Kyber protocol.
 * They can then use this key with a standard encryption algorithm (like AES) to encrypt their messages.
 * Its size is also 32 bytes.
 */
#define KYBER_SSBYTES  32   /* size in bytes of shared key */

/*
 * In Kyber, we don't just use single polynomials, we use vectors (lists) of them.
 * KYBER_POLYBYTES is the size in bytes to store one polynomial.
 * KYBER_POLYVECBYTES is the size to store a vector of 'K' polynomials.
 * So, the total size is K * (size of one polynomial).
 */
#define KYBER_POLYBYTES		384
#define KYBER_POLYVECBYTES	(KYBER_K * KYBER_POLYBYTES)

/*
 * These parameters change depending on the security level 'K'.
 *
 * KYBER_ETA1: This controls the size of the "noise" we add during encryption.
 *             Cryptography is like hiding a needle in a haystack. This parameter controls how big the haystack is.
 *             The noise makes it hard for an attacker to find the secret message.
 *
 * KYBER_POLYCOMPRESSEDBYTES: The size of a polynomial after we "compress" it.
 *                            We can squeeze our polynomials into a smaller space to save bandwidth.
 *
 * KYBER_POLYVECCOMPRESSEDBYTES: The size of a compressed vector of polynomials.
 */
#if KYBER_K == 2
#define KYBER_ETA1 3
#define KYBER_POLYCOMPRESSEDBYTES    128
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)
#elif KYBER_K == 3
#define KYBER_ETA1 2
#define KYBER_POLYCOMPRESSEDBYTES    128
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)
#elif KYBER_K == 4
#define KYBER_ETA1 2
#define KYBER_POLYCOMPRESSEDBYTES    160
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 352)
#endif

/*
 * KYBER_ETA2: This controls the size of another type of noise we add.
 *             More noise for more security!
 */
#define KYBER_ETA2 2

/*
 * These parameters define the sizes of different parts of the "IND-CPA" part of Kyber.
 * IND-CPA is a security property that means an attacker can't learn anything about your
 * encrypted messages, even if they can trick you into encrypting things for them.
 *
 * KYBER_INDCPA_MSGBYTES: The size of the message we can encrypt.
 * KYBER_INDCPA_PUBLICKEYBYTES: The size of the public key. Anyone can see this.
 * KYBER_INDCPA_SECRETKEYBYTES: The size of the secret key. Only you have this.
 * KYBER_INDCPA_BYTES: The size of the encrypted message (ciphertext).
 */
#define KYBER_INDCPA_MSGBYTES       (KYBER_SYMBYTES)
#define KYBER_INDCPA_PUBLICKEYBYTES (KYBER_POLYVECBYTES + KYBER_SYMBYTES)
#define KYBER_INDCPA_SECRETKEYBYTES (KYBER_POLYVECBYTES)
#define KYBER_INDCPA_BYTES          (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES)

/*
 * These are the final, "real-world" sizes for the public key, secret key, and ciphertext
 * for the full Kyber Key Encapsulation Mechanism (KEM).
 * A KEM is a way to create and "encapsulate" (wrap up) a shared secret to send to someone.
 *
 * KYBER_PUBLICKEYBYTES: The total size of the public key you share with others.
 * KYBER_SECRETKEYBYTES: The total size of the secret key you keep safe. It's larger than the IND-CPA
 *                       secret key because it also stores a copy of the public key and some other things
 *                       to make the process faster and more secure.
 * KYBER_CIPHERTEXTBYTES: The total size of the data you send to someone to establish a shared secret.
 */
#define KYBER_PUBLICKEYBYTES  (KYBER_INDCPA_PUBLICKEYBYTES)
/* 32 bytes of additional space to save H(pk) */
#define KYBER_SECRETKEYBYTES  (KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES + 2*KYBER_SYMBYTES)
#define KYBER_CIPHERTEXTBYTES (KYBER_INDCPA_BYTES)

#endif


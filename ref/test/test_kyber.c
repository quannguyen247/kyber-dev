#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "../kem.h"
#include "../randombytes.h"



// Print entire data as hex
static void print_hex_full(const char *label, const uint8_t *data, size_t len) {
  printf("%s: ", label);
  for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
  printf("\n");
}

static int test_keys(void)
{

  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t ss_enc[CRYPTO_BYTES];
  uint8_t ss_dec[CRYPTO_BYTES];
  uint8_t coins[2*KYBER_SYMBYTES];
  uint8_t m[KYBER_SYMBYTES];

  printf("====== KEY GENERATION STAGE ======\n\n");
  // Step 1: Generate seed
  randombytes(coins, 2*KYBER_SYMBYTES);
  print_hex_full("[Step 1] Seed generated.", coins, 2*KYBER_SYMBYTES);

  // Step 2: Generate publicseed and noiseseed
  printf("[Step 2] Generating publicseed and noiseseed...\n");
  // Simulate publicseed and noiseseed generation (details omitted)

  // Step 3: Generate matrix A from publicseed
  printf("[Step 3] Generating matrix A from publicseed...\n");
  // Simulate matrix generation (details omitted)

  // Step 4: Generate vectors s, e from noiseseed
  printf("[Step 4] Generating vectors s, e from noiseseed...\n");
  // Simulate vector generation (details omitted)

  // Step 5: Compute pk = A*s + e
  printf("[Step 5] Computing pk = A*s + e...\n");
  // Simulate pk computation (details omitted)

  // Step 6: Pack keys
  printf("[Step 6] Packing keys...\n");
  crypto_kem_keypair(pk, sk);
  print_hex_full("[Step 7] Public key pk", pk, CRYPTO_PUBLICKEYBYTES);
  print_hex_full("[Step 8] Secret key sk", sk, CRYPTO_SECRETKEYBYTES);
  printf("[Done] Key generation completed successfully.\n\n");

  printf("====== ENCAPSULATION STAGE ======\n\n");
  // Step 1: Generate random message m
  randombytes(m, KYBER_SYMBYTES);
  print_hex_full("[Step 1] Random message m", m, KYBER_SYMBYTES);

  // Step 2: Hash public key
  printf("[Step 2] Hashing public key...\n");
  // Simulate hash computation (details omitted)

  // Step 3: Generate coins and hash_pk
  printf("[Step 3] Generating coins and hash_pk...\n");
  // Simulate coins and hash_pk generation (details omitted)

  // Step 4: Generate vectors r, e1, e2 from coins
  printf("[Step 4] Generating vectors r, e1, e2 from coins...\n");
  // Simulate vector generation (details omitted)

  // Step 5: Compute u = A*r + e1
  printf("[Step 5] Computing u = A*r + e1...\n");
  // Simulate u computation (details omitted)

  // Step 6: Compute v = pk^T*r + e2 + encode(m)
  printf("[Step 6] Computing v = pk^T*r + e2 + encode(m)...\n");
  // Simulate v computation (details omitted)

  // Step 7: Pack ciphertext
  printf("[Step 7] Packing ciphertext...\n");
  crypto_kem_enc(ct, ss_enc, pk);
  print_hex_full("[Step 8] Ciphertext", ct, CRYPTO_CIPHERTEXTBYTES);
  print_hex_full("[Step 9] Shared secret (enc)", ss_enc, CRYPTO_BYTES);
  printf("[Done] Encapsulation completed successfully.\n\n");

  printf("====== DECAPSULATION STAGE ======\n\n");
  // Step 1: Unpack ciphertext
  printf("[Step 1] Unpacking ciphertext...\n");
  // Simulate unpacking (details omitted)

  // Step 2: Unpack secret key
  printf("[Step 2] Unpacking secret key...\n");
  // Simulate unpacking (details omitted)

  // Step 3: Compute m' = decode(v - u^T*s)
  printf("[Step 3] Computing m' = decode(v - u^T*s)...\n");
  // Simulate m' computation (details omitted)

  // Step 4: Generate coins from hash_pk
  printf("[Step 4] Generating coins from hash_pk...\n");
  // Simulate coins generation (details omitted)

  // Step 5: Compute u', v'
  printf("[Step 5] Computing u', v'...\n");
  // Simulate u', v' computation (details omitted)

  // Step 6: Compare u, v with u', v'...
  printf("[Step 6] Comparing u, v with u', v'...\n");
  crypto_kem_dec(ss_dec, ct, sk);
  print_hex_full("[Step 7] Shared secret (dec)", ss_dec, CRYPTO_BYTES);

  if(memcmp(ss_enc, ss_dec, CRYPTO_BYTES)) {
    printf("[Error] Shared secrets do not match!\n");
    return 1;
  }

  printf("[Done] Decapsulation completed successfully.\n");
  printf("[Success] Shared secrets match.\n");
  return 0;
}

static int test_invalid_sk_a(void)
{
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t key_a[CRYPTO_BYTES];
  uint8_t key_b[CRYPTO_BYTES];

  //Alice generates a public key
  crypto_kem_keypair(pk, sk);

  //Bob derives a secret key and creates a response
  crypto_kem_enc(ct, key_b, pk);

  //Replace secret key with random values
  randombytes(sk, CRYPTO_SECRETKEYBYTES);

  //Alice uses Bobs response to get her shared key
  crypto_kem_dec(key_a, ct, sk);

  if(!memcmp(key_a, key_b, CRYPTO_BYTES)) {
    printf("ERROR invalid sk\n");
    return 1;
  }

  return 0;
}

static int test_invalid_ciphertext(void)
{
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t key_a[CRYPTO_BYTES];
  uint8_t key_b[CRYPTO_BYTES];
  uint8_t b;
  size_t pos;

  do {
    randombytes(&b, sizeof(uint8_t));
  } while(!b);
  randombytes((uint8_t *)&pos, sizeof(size_t));

  //Alice generates a public key
  crypto_kem_keypair(pk, sk);

  //Bob derives a secret key and creates a response
  crypto_kem_enc(ct, key_b, pk);

  //Change some byte in the ciphertext (i.e., encapsulated key)
  ct[pos % CRYPTO_CIPHERTEXTBYTES] ^= b;

  //Alice uses Bobs response to get her shared key
  crypto_kem_dec(key_a, ct, sk);

  if(!memcmp(key_a, key_b, CRYPTO_BYTES)) {
    printf("ERROR invalid ciphertext\n");
    return 1;
  }

  return 0;
}

int main(void)
{
  int r = test_keys();
  printf("CRYPTO_SECRETKEYBYTES:  %d\n", CRYPTO_SECRETKEYBYTES);
  printf("CRYPTO_PUBLICKEYBYTES:  %d\n", CRYPTO_PUBLICKEYBYTES);
  printf("CRYPTO_CIPHERTEXTBYTES: %d\n", CRYPTO_CIPHERTEXTBYTES);

  printf("\n====== TESTING INVALID SECRET KEY ======\n");
  if (test_invalid_sk_a() == 0) {
    printf("[Error] test_invalid_sk_a did not fail as expected!\n");
  } else {
    printf("[Success] test_invalid_sk_a failed as expected.\n");
  }

  printf("\n====== TESTING INVALID CIPHERTEXT ======\n");
  if (test_invalid_ciphertext() == 0) {
    printf("[Error] test_invalid_ciphertext did not fail as expected!\n");
  } else {
    printf("[Success] test_invalid_ciphertext failed as expected.\n");
  }

  return r;
}

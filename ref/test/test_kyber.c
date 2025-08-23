#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "../kem.h"
#include "../randombytes.h"



// Print entire data as hex
static void print_hex_full(const char *label, const uint8_t *data, size_t len) {
  printf("\r%s: ", label);
  for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
  printf("\r\n");
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

  printf("\r====== KEY GENERATION STAGE ======\r\n\r\n");
  // Step 1: Generate seed
  randombytes(coins, 2*KYBER_SYMBYTES);
  print_hex_full("[Step 1] Seed generated.", coins, 2*KYBER_SYMBYTES);

  printf("\r[Step 2] Generating publicseed and noiseseed...\r\n");
  printf("\r[Step 3] Generating matrix A from publicseed...\r\n");
  printf("\r[Step 4] Generating vectors s, e from noiseseed...\r\n");
  printf("\r[Step 5] Computing pk = A*s + e...\r\n");
  printf("\r[Step 6] Packing keys...\r\n");
  crypto_kem_keypair(pk, sk);
  print_hex_full("[Step 7] Public key pk", pk, CRYPTO_PUBLICKEYBYTES);
  print_hex_full("[Step 8] Secret key sk", sk, CRYPTO_SECRETKEYBYTES);
  printf("\r[Done] Key generation completed successfully.\r\n\r\n");

  printf("\r====== ENCAPSULATION STAGE ======\r\n\r\n");
  randombytes(m, KYBER_SYMBYTES);
  print_hex_full("[Step 1] Random message m", m, KYBER_SYMBYTES);
  printf("\r[Step 2] Hashing public key...\r\n");
  printf("\r[Step 3] Generating coins and hash_pk...\r\n");
  printf("\r[Step 4] Generating vectors r, e1, e2 from coins...\r\n");
  printf("\r[Step 5] Computing u = A*r + e1...\r\n");
  printf("\r[Step 6] Computing v = pk^T*r + e2 + encode(m)...\r\n");
  printf("\r[Step 7] Packing ciphertext...\r\n");
  crypto_kem_enc(ct, ss_enc, pk);
  print_hex_full("[Step 8] Ciphertext", ct, CRYPTO_CIPHERTEXTBYTES);
  print_hex_full("[Step 9] Shared secret (enc)", ss_enc, CRYPTO_BYTES);
  printf("\r[Done] Encapsulation completed successfully.\r\n\r\n");

  printf("\r====== DECAPSULATION STAGE ======\r\n\r\n");
  printf("\r[Step 1] Unpacking ciphertext...\r\n");
  printf("\r[Step 2] Unpacking secret key...\r\n");
  printf("\r[Step 3] Computing m' = decode(v - u^T*s)...\r\n");
  printf("\r[Step 4] Generating coins from hash_pk...\r\n");
  printf("\r[Step 5] Computing u', v'...\r\n");
  printf("\r[Step 6] Comparing u, v with u', v'...\r\n");
  crypto_kem_dec(ss_dec, ct, sk);
  print_hex_full("[Step 7] Shared secret (dec)", ss_dec, CRYPTO_BYTES);

  if(memcmp(ss_enc, ss_dec, CRYPTO_BYTES)) {
    printf("\r[Error] Shared secrets do not match!\r\n");
    return 1;
  }

  printf("\r[Done] Decapsulation completed successfully.\r\n");
  printf("\r[Success] Shared secrets match.\r\n");
  return 0;
}

static int test_invalid_sk_a(void)
{
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t key_a[CRYPTO_BYTES];
  uint8_t key_b[CRYPTO_BYTES];

  // Alice generates a public key
  crypto_kem_keypair(pk, sk);

  // Bob derives a secret key and creates a response
  crypto_kem_enc(ct, key_b, pk);

  // Replace secret key with random values
  printf("\rOriginal secret key sk: \r\n");
  print_hex_full("sk", sk, CRYPTO_SECRETKEYBYTES);
  randombytes(sk, CRYPTO_SECRETKEYBYTES);
  printf("\rModified secret key sk: \r\n");
  print_hex_full("sk", sk, CRYPTO_SECRETKEYBYTES);

  // Alice uses Bob's response to get her shared key
  crypto_kem_dec(key_a, ct, sk);

  printf("\rDecapsulated key_a: \r\n");
  print_hex_full("key_a", key_a, CRYPTO_BYTES);
  printf("\rExpected key_b: \r\n");
  print_hex_full("key_b", key_b, CRYPTO_BYTES);

  if (memcmp(key_a, key_b, CRYPTO_BYTES) == 0) {
    printf("\rERROR: test_invalid_sk_a did not fail as expected!\r\n");
    return 1;
  }

  printf("\r[Success] test_invalid_sk_a failed as expected.\r\n");
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

  // Alice generates a public key
  crypto_kem_keypair(pk, sk);

  // Bob derives a secret key and creates a response
  crypto_kem_enc(ct, key_b, pk);

  // Change some byte in the ciphertext (i.e., encapsulated key)
  printf("\rOriginal ciphertext ct: \r\n");
  print_hex_full("ct", ct, CRYPTO_CIPHERTEXTBYTES);
  do {
    randombytes(&b, sizeof(uint8_t));
  } while (!b);
  randombytes((uint8_t *)&pos, sizeof(size_t));
  ct[pos % CRYPTO_CIPHERTEXTBYTES] ^= b;
  printf("\rModified ciphertext ct: \r\n");
  print_hex_full("ct", ct, CRYPTO_CIPHERTEXTBYTES);

  // Alice uses Bob's response to get her shared key
  crypto_kem_dec(key_a, ct, sk);

  printf("\rDecapsulated key_a: \r\n");
  print_hex_full("key_a", key_a, CRYPTO_BYTES);
  printf("\rExpected key_b: \r\n");
  print_hex_full("key_b", key_b, CRYPTO_BYTES);

  if (memcmp(key_a, key_b, CRYPTO_BYTES) == 0) {
    printf("\rERROR: test_invalid_ciphertext did not fail as expected!\r\n");
    return 1;
  }

  printf("\r[Success] test_invalid_ciphertext failed as expected.\r\n");
  return 0;
}

int main(void)
{
  int r = test_keys();
  // printf("\rCRYPTO_SECRETKEYBYTES:  %d\r\n", CRYPTO_SECRETKEYBYTES);
  // printf("\rCRYPTO_PUBLICKEYBYTES:  %d\r\n", CRYPTO_PUBLICKEYBYTES);
  // printf("\rCRYPTO_CIPHERTEXTBYTES: %d\r\n", CRYPTO_CIPHERTEXTBYTES);

  printf("\r\n====== TESTING INVALID SECRET KEY ======\r\n");
  test_invalid_sk_a();

  printf("\r\n====== TESTING INVALID CIPHERTEXT ======\r\n");
  test_invalid_ciphertext();

  return r;
}

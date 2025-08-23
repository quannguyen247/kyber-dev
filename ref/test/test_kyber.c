#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "../kem.h"
#include "../randombytes.h"


// Helper to print hex
static void print_hex(const char *label, const uint8_t *data, size_t len) {
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

  printf("\n=== FLOW: Keypair Generation ===\n");
  randombytes(coins, 2*KYBER_SYMBYTES);
  print_hex("seed", coins, KYBER_SYMBYTES);
  // publicseed, noiseseed sẽ được sinh trong hàm keypair_derand
  crypto_kem_keypair(pk, sk);
  print_hex("pk", pk, CRYPTO_PUBLICKEYBYTES);
  print_hex("sk", sk, CRYPTO_SECRETKEYBYTES);

  printf("\n=== FLOW: Encapsulation ===\n");
  randombytes(m, KYBER_SYMBYTES);
  print_hex("message m", m, KYBER_SYMBYTES);
  crypto_kem_enc(ct, ss_enc, pk);
  print_hex("ciphertext", ct, CRYPTO_CIPHERTEXTBYTES);
  print_hex("shared secret (enc)", ss_enc, CRYPTO_BYTES);

  printf("\n=== FLOW: Decapsulation ===\n");
  crypto_kem_dec(ss_dec, ct, sk);
  print_hex("shared secret (dec)", ss_dec, CRYPTO_BYTES);

  if(memcmp(ss_enc, ss_dec, CRYPTO_BYTES)) {
    printf("ERROR: Shared secrets do not match!\n");
    return 1;
  }
  printf("SUCCESS: Shared secrets match.\n");
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
  printf("CRYPTO_SECRETKEYBYTES:  %d\n",CRYPTO_SECRETKEYBYTES);
  printf("CRYPTO_PUBLICKEYBYTES:  %d\n",CRYPTO_PUBLICKEYBYTES);
  printf("CRYPTO_CIPHERTEXTBYTES: %d\n",CRYPTO_CIPHERTEXTBYTES);
  return r;
}

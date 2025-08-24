#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "../kem.h"
#include "../randombytes.h"

static int test_keys(void)
{

  FILE *fout = fopen("test/output.txt", "w");
  if(!fout) {
    printf("File error\n");
    return 1;
  }

  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t key_a[CRYPTO_BYTES];
  uint8_t key_b[CRYPTO_BYTES];

  // KeyGen Stage
  crypto_kem_keypair(pk, sk);
  fprintf(fout, "KeyGen Stage:\n");
  fprintf(fout, "- Input: None\n");
  fprintf(fout, "- Output:\n");
  fprintf(fout, "* Public Key: ");
  for(size_t i=0; i<CRYPTO_PUBLICKEYBYTES; i++) fprintf(fout, "%02x", pk[i]);
  fprintf(fout, "\n* Secret Key: ");
  for(size_t i=0; i<CRYPTO_SECRETKEYBYTES; i++) fprintf(fout, "%02x", sk[i]);
  fprintf(fout, "\n\n");

  // Encapsulation Stage
  crypto_kem_enc(ct, key_b, pk);
  fprintf(fout, "Encapsulation Stage (A):\n");
  fprintf(fout, "- Input: pk\n");
  fprintf(fout, "- Output: \n");
  fprintf(fout, "* Ciphertext: ");
  for(size_t i=0; i<CRYPTO_CIPHERTEXTBYTES; i++) fprintf(fout, "%02x", ct[i]);
  fprintf(fout, "\n* Shared Secret: ");
  for(size_t i=0; i<CRYPTO_BYTES; i++) fprintf(fout, "%02x", key_b[i]);
  fprintf(fout, "\n\n");

  // Make secret key sk or ciphertext ct invalid to test, delete it to make valid
  //ct[0] ^= 0xFF; // sk[0] ^= 0xFF;

  // Decapsulation Stage
  crypto_kem_dec(key_a, ct, sk);
  fprintf(fout, "Decapsulation Stage (B):\n");
  fprintf(fout, "- Input: ct, sk\n");
  fprintf(fout, "- Output: \n* Shared Secret: ");
  for(size_t i=0; i<CRYPTO_BYTES; i++) fprintf(fout, "%02x", key_a[i]);
  fprintf(fout, "\n");

  // Compare shared secret
  if(memcmp(key_a, key_b, CRYPTO_BYTES)) {
    printf("\nERROR: shared secret mismatch!\n");
    fprintf(fout, "\nResult: shared secret mismatch!\n");
    fclose(fout);
    return 1;
  } else {
    printf("\nSUCCESS: shared secret match!\n");
    fprintf(fout, "\nResult: shared secret match!\n");
    fclose(fout);
    return 0;
  }

  return 0;
}

// reference test functions:
/* static int test_invalid_sk_a(void)
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
    printf("ERROR: invalid sk\n");
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
    printf("ERROR: invalid ciphertext\n");
    return 1;
  }

  return 0;
} */

int main(void)
{
  
  int r;
  r = test_keys();
  // r |= test_invalid_sk_a();
  // r |= test_invalid_ciphertext(); 
  if(r)
    return 1;

  //printf("CRYPTO_SECRETKEYBYTES:  %d\n",CRYPTO_SECRETKEYBYTES);
  //printf("CRYPTO_PUBLICKEYBYTES:  %d\n",CRYPTO_PUBLICKEYBYTES);
  //printf("CRYPTO_CIPHERTEXTBYTES: %d\n",CRYPTO_CIPHERTEXTBYTES);

  return 0;
}

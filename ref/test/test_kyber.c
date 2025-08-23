#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "../kem.h"
#include "../randombytes.h"

// File pointer for output.txt
static FILE *output_file;

// Print entire data as hex and write to output.txt (for variable content)
static void print_hex_to_file(const char *label, const uint8_t *data, size_t len) {
  fprintf(output_file, "%s: ", label);
  for (size_t i = 0; i < len; i++) fprintf(output_file, "%02x", data[i]);
  fprintf(output_file, "\n");
}

// Print entire data as hex to terminal only
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

  // ====== KEY GENERATION STAGE ======
  printf("\r====== KEY GENERATION STAGE ======\r\n\r\n");
  randombytes(coins, 2*KYBER_SYMBYTES);

  // Write KeyGen section to output.txt
  fprintf(output_file, "KeyGen Stage:\n");
  fprintf(output_file, "Input: None\n");
  fprintf(output_file, "Output:\n");
  fprintf(output_file, "  Public Key: pk\n");
  fprintf(output_file, "  Secret Key: sk\n");
  fprintf(output_file, "Content:\n");
  print_hex_to_file("Public Key", pk, CRYPTO_PUBLICKEYBYTES); // Sẽ được sinh ra sau
  print_hex_to_file("Secret Key", sk, CRYPTO_SECRETKEYBYTES); // Sẽ được sinh ra sau
  fprintf(output_file, "\n");

  // Step 1: Generate seed
  printf("\r[Step 1] Generate seed.\r\n");
  printf("\r[Step 2] Generating publicseed and noiseseed...\r\n");
  printf("\r[Step 3] Generating matrix A from publicseed...\r\n");
  printf("\r[Step 4] Generating vectors s, e from noiseseed...\r\n");
  printf("\r[Step 5] Computing pk = A*s + e...\r\n");
  printf("\r[Step 6] Packing keys...\r\n");
  crypto_kem_keypair(pk, sk);
  // Ghi lại giá trị pk, sk vào file (ghi đè lại dòng cũ)
  fseek(output_file, 0, SEEK_SET);
  fprintf(output_file, "KeyGen Stage:\n");
  fprintf(output_file, "Input: None\n");
  fprintf(output_file, "Output:\n");
  fprintf(output_file, "  Public Key: pk\n");
  fprintf(output_file, "  Secret Key: sk\n");
  fprintf(output_file, "Content:\n");
  print_hex_to_file("Public Key", pk, CRYPTO_PUBLICKEYBYTES);
  print_hex_to_file("Secret Key", sk, CRYPTO_SECRETKEYBYTES);
  fprintf(output_file, "\n");
  fseek(output_file, 0, SEEK_END);

  printf("\r[Done] Key generation completed successfully.\r\n\r\n");

  // ====== ENCAPSULATION STAGE ======
  printf("\r====== ENCAPSULATION STAGE ======\r\n\r\n");
  randombytes(m, KYBER_SYMBYTES);

  // Write Encapsulation section to output.txt
  fprintf(output_file, "Encapsulation Stage:\n");
  fprintf(output_file, "Input:\n");
  fprintf(output_file, "  Public Key: pk\n");
  fprintf(output_file, "Output:\n");
  fprintf(output_file, "  Ciphertext: ct\n");
  fprintf(output_file, "  Shared Secret: ss_enc\n");
  fprintf(output_file, "Content:\n");
  print_hex_to_file("Public Key", pk, CRYPTO_PUBLICKEYBYTES);
  print_hex_to_file("Ciphertext", ct, CRYPTO_CIPHERTEXTBYTES); // Sẽ được sinh ra sau
  print_hex_to_file("Shared Secret", ss_enc, CRYPTO_BYTES); // Sẽ được sinh ra sau
  fprintf(output_file, "\n");

  printf("\r[Step 1] Generate random message m.\r\n");
  printf("\r[Step 2] Hashing public key...\r\n");
  printf("\r[Step 3] Generating coins and hash_pk...\r\n");
  printf("\r[Step 4] Generating vectors r, e1, e2 from coins...\r\n");
  printf("\r[Step 5] Computing u = A*r + e1...\r\n");
  printf("\r[Step 6] Computing v = pk^T*r + e2 + encode(m)...\r\n");
  printf("\r[Step 7] Packing ciphertext...\r\n");
  crypto_kem_enc(ct, ss_enc, pk);
  // Ghi lại giá trị ct, ss_enc vào file (ghi đè lại dòng cũ)
  fseek(output_file, 0, SEEK_END);
  print_hex_to_file("Ciphertext", ct, CRYPTO_CIPHERTEXTBYTES);
  print_hex_to_file("Shared Secret", ss_enc, CRYPTO_BYTES);
  fprintf(output_file, "\n");

  printf("\r[Done] Encapsulation completed successfully.\r\n\r\n");

  // ====== DECAPSULATION STAGE ======
  printf("\r====== DECAPSULATION STAGE ======\r\n\r\n");

  // Write Decapsulation section to output.txt
  fprintf(output_file, "Decapsulation Stage:\n");
  fprintf(output_file, "Input:\n");
  fprintf(output_file, "  Ciphertext: ct\n");
  fprintf(output_file, "  Secret Key: sk\n");
  fprintf(output_file, "Output:\n");
  fprintf(output_file, "  Shared Secret: ss_dec\n");
  fprintf(output_file, "Content:\n");
  print_hex_to_file("Ciphertext", ct, CRYPTO_CIPHERTEXTBYTES);
  print_hex_to_file("Secret Key", sk, CRYPTO_SECRETKEYBYTES);
  print_hex_to_file("Shared Secret", ss_dec, CRYPTO_BYTES); // Sẽ được sinh ra sau
  fprintf(output_file, "\n");

  printf("\r[Step 1] Unpacking ciphertext...\r\n");
  printf("\r[Step 2] Unpacking secret key...\r\n");
  printf("\r[Step 3] Computing m' = decode(v - u^T*s)...\r\n");
  printf("\r[Step 4] Generating coins from hash_pk...\r\n");
  printf("\r[Step 5] Computing u', v'...\r\n");
  printf("\r[Step 6] Comparing u, v with u', v'...\r\n");
  crypto_kem_dec(ss_dec, ct, sk);
  // Ghi lại giá trị ss_dec vào file (ghi đè lại dòng cũ)
  fseek(output_file, 0, SEEK_END);
  print_hex_to_file("Shared Secret", ss_dec, CRYPTO_BYTES);
  fprintf(output_file, "\n");

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
  randombytes(sk, CRYPTO_SECRETKEYBYTES);

  // Alice uses Bob's response to get her shared key
  crypto_kem_dec(key_a, ct, sk);

  if (memcmp(key_a, key_b, CRYPTO_BYTES) == 0) {
    printf("\r[Fail] test_invalid_sk_a: shared secrets matched (should not).\r\n");
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
  do {
    randombytes(&b, sizeof(uint8_t));
  } while (!b);
  randombytes((uint8_t *)&pos, sizeof(size_t));
  ct[pos % CRYPTO_CIPHERTEXTBYTES] ^= b;

  // Alice uses Bob's response to get her shared key
  crypto_kem_dec(key_a, ct, sk);

  if (memcmp(key_a, key_b, CRYPTO_BYTES) == 0) {
    printf("\r[Fail] test_invalid_ciphertext: shared secrets matched (should not).\r\n");
    return 1;
  }

  printf("\r[Success] test_invalid_ciphertext failed as expected.\r\n");
  return 0;
}

int main(void)
{
  output_file = fopen("output.txt", "w");
  if (!output_file) {
    perror("Failed to open output.txt");
    return 1;
  }

  int r = test_keys();

  printf("\r\n====== TESTING INVALID SECRET KEY ======\r\n");
  test_invalid_sk_a();

  printf("\r\n====== TESTING INVALID CIPHERTEXT ======\r\n");
  test_invalid_ciphertext();

  fclose(output_file);
  return r;
}

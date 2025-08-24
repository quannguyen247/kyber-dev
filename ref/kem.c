#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "params.h"
#include "kem.h"
#include "indcpa.h"
#include "verify.h"
#include "symmetric.h"
#include "randombytes.h"
// hàm có đuôi_derand là "derandomized", nghĩa là chúng
// nhận nguồn dữ liệu ngẫu nhiên từ bên ngoài, trong khi
// hàm không có đuôi _derand sẽ tự tạo ra dữ liệu ngẫu nhiên bên trong.
// [không đuôi _derand] sẽ gọi [có đuôi _derand]
/*************************************************
* Name:        crypto_kem_keypair_derand
*
* Description: Generates public and private key
*              for CCA-secure Kyber key encapsulation mechanism
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key
*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
*              - uint8_t *coins: pointer to input randomness
*                (an already allocated array filled with 2*KYBER_SYMBYTES random bytes)
**
* Returns 0 (success)
**************************************************/
int crypto_kem_keypair_derand(uint8_t *pk,
                              uint8_t *sk,
                              const uint8_t *coins)
{
  //Gọi indcpa_keypair_derand để tạo cặp khóa PKE cơ bản.
  indcpa_keypair_derand(pk, sk, coins);
//Mở rộng khóa bí mật:
  memcpy(sk+KYBER_INDCPA_SECRETKEYBYTES, pk, KYBER_PUBLICKEYBYTES);
  hash_h(sk+KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
  /* Value z for pseudo-random output on reject */
  memcpy(sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, coins+KYBER_SYMBYTES, KYBER_SYMBYTES);
  return 0;
}

/*************************************************
* Name:        crypto_kem_keypair
*
* Description: Generates public and private key
*              for CCA-secure Kyber key encapsulation mechanism
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key
*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_keypair(uint8_t *pk,
                       uint8_t *sk)
{
  uint8_t coins[2*KYBER_SYMBYTES];
  // 1. Tao seed ngau nhien
  printf("KEM Keygen: 1. Generating random seed...\n");
  randombytes(coins, 2*KYBER_SYMBYTES);
  crypto_kem_keypair_derand(pk, sk, coins);
  return 0;
}

/*************************************************
* Name:        crypto_kem_enc_derand
*
* Description: Generates cipher text and shared
*              secret for given public key
*
* Arguments:   - uint8_t *ct: pointer to output cipher text
*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
*              - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of KYBER_SSBYTES bytes)
*              - const uint8_t *pk: pointer to input public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*              - const uint8_t *coins: pointer to input randomness
*                (an already allocated array filled with KYBER_SYMBYTES random bytes)
**
* Returns 0 (success)
**************************************************/
int crypto_kem_enc_derand(uint8_t *ct,
                          uint8_t *ss,
                          const uint8_t *pk,
                          const uint8_t *coins)
{
  uint8_t buf[2*KYBER_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2*KYBER_SYMBYTES];

  memcpy(buf, coins, KYBER_SYMBYTES);

  // 2. Hash khoa cong khai
  printf("KEM Enc: 2. Hashing public key...\n");
  hash_h(buf+KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
  // 3. Sinh coins tu m va hash_pk
  printf("KEM Enc: 3. Generating coins for IND-CPA encryption...\n");
  hash_g(kr, buf, 2*KYBER_SYMBYTES);

  // 4. Sinh vector r, e1, e2 tu coins (ben trong indcpa_enc)
  // 5. Tinh u = A^T*r + e1 (ben trong indcpa_enc)
  // 6. Tinh v = pk^T*r + e2 + encode(m) (ben trong indcpa_enc)
  // 7. Dong goi ciphertext (ben trong indcpa_enc)
  indcpa_enc(ct, buf, pk, kr+KYBER_SYMBYTES);

  // 8. Tinh shared secret
  printf("KEM Enc: 8. Calculating shared secret.\n");
  memcpy(ss,kr,KYBER_SYMBYTES);
  return 0;
}

/*************************************************
* Name:        crypto_kem_enc
*
* Description: Generates cipher text and shared
*              secret for given public key
*
* Arguments:   - uint8_t *ct: pointer to output cipher text
*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
*              - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of KYBER_SSBYTES bytes)
*              - const uint8_t *pk: pointer to input public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_enc(uint8_t *ct,
                   uint8_t *ss,
                   const uint8_t *pk)
{
  uint8_t coins[KYBER_SYMBYTES];
  // 1. Sinh thong diep ngau nhien
  printf("KEM Enc: 1. Generating random message...\n");
  randombytes(coins, KYBER_SYMBYTES);
  crypto_kem_enc_derand(ct, ss, pk, coins);
  return 0;
}

/*************************************************
* Name:        crypto_kem_dec
*
* Description: Generates shared secret for given
*              cipher text and private key
*
* Arguments:   - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of KYBER_SSBYTES bytes)
*              - const uint8_t *ct: pointer to input cipher text
*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
*              - const uint8_t *sk: pointer to input private key
*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
*
* Returns 0.
*
* On failure, ss will contain a pseudo-random value.
**************************************************/
int crypto_kem_dec(uint8_t *ss,
                   const uint8_t *ct,
                   const uint8_t *sk)
{
  int fail;
  uint8_t buf[2*KYBER_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2*KYBER_SYMBYTES];
//  uint8_t cmp[KYBER_CIPHERTEXTBYTES+KYBER_SYMBYTES];
  uint8_t cmp[KYBER_CIPHERTEXTBYTES];
  const uint8_t *pk = sk+KYBER_INDCPA_SECRETKEYBYTES;

  // 1. Giai nen ciphertext (ben trong indcpa_dec)
  // 2. Lay cac thanh phan bi mat tu sk (khong co ham rieng, truy cap truc tiep)
  // 3. Giai ma ciphertext (ben trong indcpa_dec)
  indcpa_dec(buf, ct, sk);

  // 4. Sinh lai coins tu m' va hash_pk
  printf("KEM Dec: 4. Re-generating coins for verification...\n");
  memcpy(buf+KYBER_SYMBYTES, sk+KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES, KYBER_SYMBYTES);
  hash_g(kr, buf, 2*KYBER_SYMBYTES);

  // 5. Sinh lai r', e1', e2' tu coins (ben trong indcpa_enc)
  // 6. Tinh lai u', v' (ben trong indcpa_enc)
  printf("KEM Dec: 6. Re-encrypting to get candidate ciphertext...\n");
  indcpa_enc(cmp, buf, pk, kr+KYBER_SYMBYTES);

  // 7. So sanh (u, v) voi (u', v')
  printf("KEM Dec: 7. Verifying ciphertexts...\n");
  fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

  /* Compute rejection key */
  rkprf(ss,sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES,ct);

  /* Copy true key to return buffer if fail is false */
  cmov(ss,kr,KYBER_SYMBYTES,!fail);

  return 0;
}

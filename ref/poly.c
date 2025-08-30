#include <stdint.h>
#include "params.h"
#include "poly.h"
#include "ntt.h"
#include "reduce.h"
#include "cbd.h"
#include "symmetric.h"
#include "verify.h"

/*************************************************
* Name:        poly_compress
*
* Description: Compression and subsequent serialization of a polynomial.
*              This function takes a polynomial and "squishes" it into a smaller
*              number of bytes. Think of it like zipping a file to save space.
*              This is useful for making our public keys and ciphertexts smaller.
*
* Arguments:   - uint8_t *r: pointer to the output byte array where the
*                            compressed polynomial will be stored.
*              - const poly *a: pointer to the input polynomial to be compressed.
**************************************************/
void poly_compress(uint8_t r[KYBER_POLYCOMPRESSEDBYTES], const poly *a)
{
  unsigned int i,j;
  int16_t u;
  uint32_t d0;
  uint8_t t[8];

#if (KYBER_POLYCOMPRESSEDBYTES == 128)
  // We process the polynomial's 256 coefficients in chunks of 8.
  for(i=0;i<KYBER_N/8;i++) {
    for(j=0;j<8;j++) {
      // Get a coefficient. The coefficients can be small negative numbers,
      // so we map them to a positive range [0, KYBER_Q-1].
      u  = a->coeffs[8*i+j];
      u += (u >> 15) & KYBER_Q;

      // This is a clever math trick to compress a 12-bit coefficient (0-3328)
      // into a 4-bit value (0-15). We lose some precision, but that's okay here.
      d0 = u << 4;
      d0 += 1665;
      d0 *= 80635;
      d0 >>= 28;
      t[j] = d0 & 0xf;
    }

    // Pack two 4-bit values into one byte.
    r[0] = t[0] | (t[1] << 4);
    r[1] = t[2] | (t[3] << 4);
    r[2] = t[4] | (t[5] << 4);
    r[3] = t[6] | (t[7] << 4);
    r += 4; // Move to the next 4 bytes of the output.
  }
#elif (KYBER_POLYCOMPRESSEDBYTES == 160)
  // This is a similar process but for a different security level (Kyber-1024),
  // where we compress each coefficient to 5 bits instead of 4.
  for(i=0;i<KYBER_N/8;i++) {
    for(j=0;j<8;j++) {
      u  = a->coeffs[8*i+j];
      u += (u >> 15) & KYBER_Q;

      // Compress a 12-bit coefficient into a 5-bit value (0-31).
      d0 = u << 5;
      d0 += 1664;
      d0 *= 40318;
      d0 >>= 27;
      t[j] = d0 & 0x1f;
    }

    // Pack eight 5-bit values into five bytes (8 * 5 = 40 bits = 5 bytes).
    r[0] = (t[0] >> 0) | (t[1] << 5);
    r[1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
    r[2] = (t[3] >> 1) | (t[4] << 4);
    r[3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
    r[4] = (t[6] >> 2) | (t[7] << 3);
    r += 5; // Move to the next 5 bytes of the output.
  }
#else
#error "KYBER_POLYCOMPRESSEDBYTES needs to be in {128, 160}"
#endif
}

/*************************************************
* Name:        poly_decompress
*
* Description: De-serialization and subsequent decompression of a polynomial;
*              This is the reverse of poly_compress. It takes a compressed
*              byte array and "un-squishes" it back into a full polynomial.
*
* Arguments:   - poly *r: pointer to the output polynomial.
*              - const uint8_t *a: pointer to the input byte array that holds
*                                  the compressed polynomial.
**************************************************/
void poly_decompress(poly *r, const uint8_t a[KYBER_POLYCOMPRESSEDBYTES])
{
  unsigned int i;

#if (KYBER_POLYCOMPRESSEDBYTES == 128)
  // We process the compressed data in chunks of 1 byte, which contains 2 coefficients.
  for(i=0;i<KYBER_N/2;i++) {
    // Unpack the first 4-bit value, scale it back up to an approximate 12-bit coefficient.
    r->coeffs[2*i+0] = (((uint16_t)(a[0] & 15)*KYBER_Q) + 8) >> 4;
    // Unpack the second 4-bit value.
    r->coeffs[2*i+1] = (((uint16_t)(a[0] >> 4)*KYBER_Q) + 8) >> 4;
    a += 1; // Move to the next byte of the input.
  }
#elif (KYBER_POLYCOMPRESSEDBYTES == 160)
  unsigned int j;
  uint8_t t[8];
  // We process the compressed data in chunks of 5 bytes, which contains 8 coefficients.
  for(i=0;i<KYBER_N/8;i++) {
    // Unpack five bytes back into eight 5-bit values.
    t[0] = (a[0] >> 0);
    t[1] = (a[0] >> 5) | (a[1] << 3);
    t[2] = (a[1] >> 2);
    t[3] = (a[1] >> 7) | (a[2] << 1);
    t[4] = (a[2] >> 4) | (a[3] << 4);
    t[5] = (a[3] >> 1);
    t[6] = (a[3] >> 6) | (a[4] << 2);
    t[7] = (a[4] >> 3);
    a += 5; // Move to the next 5 bytes of the input.

    // For each 5-bit value, scale it back up to an approximate 12-bit coefficient.
    for(j=0;j<8;j++)
      r->coeffs[8*i+j] = ((uint32_t)(t[j] & 31)*KYBER_Q + 16) >> 5;
  }
#else
#error "KYBER_POLYCOMPRESSEDBYTES needs to be in {128, 160}"
#endif
}

/*************************************************
* Name:        poly_tobytes
*
* Description: Serialization of a polynomial.
*              This function converts a polynomial into a sequence of bytes
*              without any lossy compression. It's like saving a document
*              in a perfect, uncompressed format.
*
* Arguments:   - uint8_t *r: pointer to the output byte array.
*              - const poly *a: pointer to the input polynomial.
**************************************************/
void poly_tobytes(uint8_t r[KYBER_POLYBYTES], const poly *a)
{
  unsigned int i;
  uint16_t t0, t1;

  // Each coefficient is 12 bits. We can pack two 12-bit coefficients
  // into three bytes (2 * 12 = 24 bits = 3 * 8).
  for(i=0;i<KYBER_N/2;i++) {
    // Get two coefficients, make sure they are in the positive range [0, Q-1].
    t0  = a->coeffs[2*i];
    t0 += ((int16_t)t0 >> 15) & KYBER_Q;
    t1 = a->coeffs[2*i+1];
    t1 += ((int16_t)t1 >> 15) & KYBER_Q;

    // Pack the 12 bits of t0 and 12 bits of t1 into 3 bytes.
    r[3*i+0] = (t0 >> 0); // First 8 bits of t0.
    r[3*i+1] = (t0 >> 8) | (t1 << 4); // Last 4 bits of t0 and first 4 bits of t1.
    r[3*i+2] = (t1 >> 4); // Last 8 bits of t1.
  }
}

/*************************************************
* Name:        poly_frombytes
*
* Description: De-serialization of a polynomial.
*              This is the reverse of poly_tobytes. It takes a byte array
*              and perfectly reconstructs the original polynomial.
*
* Arguments:   - poly *r: pointer to the output polynomial.
*              - const uint8_t *a: pointer to the input byte array.
**************************************************/
void poly_frombytes(poly *r, const uint8_t a[KYBER_POLYBYTES])
{
  unsigned int i;
  // We process the input byte array in chunks of 3 bytes to get 2 coefficients.
  for(i=0;i<KYBER_N/2;i++) {
    // Unpack 3 bytes back into two 12-bit coefficients.
    r->coeffs[2*i]   = ((a[3*i+0] >> 0) | ((uint16_t)a[3*i+1] << 8)) & 0xFFF;
    r->coeffs[2*i+1] = ((a[3*i+1] >> 4) | ((uint16_t)a[3*i+2] << 4)) & 0xFFF;
  }
}

/*************************************************
* Name:        poly_frommsg
*
* Description: Convert a 32-byte message into a polynomial.
*              This is a way to encode our secret message (which is just a bunch of bits)
*              as a polynomial. Each bit of the message becomes a coefficient in the polynomial.
*
* Arguments:   - poly *r: pointer to the output polynomial.
*              - const uint8_t *msg: pointer to the 32-byte input message.
**************************************************/
void poly_frommsg(poly *r, const uint8_t msg[KYBER_INDCPA_MSGBYTES])
{
  unsigned int i,j;

#if (KYBER_INDCPA_MSGBYTES != KYBER_N/8)
#error "KYBER_INDCPA_MSGBYTES must be equal to KYBER_N/8 bytes!"
#endif

  // For each bit in the 32-byte message...
  for(i=0;i<KYBER_N/8;i++) {
    for(j=0;j<8;j++) {
      // If the bit is 0, the coefficient is 0.
      // If the bit is 1, the coefficient is (KYBER_Q+1)/2, which is about half of Q.
      // This encoding makes it easy to recover the bit later.
      r->coeffs[8*i+j] = 0;
      cmov_int16(r->coeffs+8*i+j, ((KYBER_Q+1)/2), (msg[i] >> j)&1);
    }
  }
}

/*************************************************
* Name:        poly_tomsg
*
* Description: Convert a polynomial back into a 32-byte message.
*              This is the reverse of poly_frommsg. It decodes the polynomial
*              to get the original secret message back.
*
* Arguments:   - uint8_t *msg: pointer to the output 32-byte message.
*              - const poly *a: pointer to the input polynomial.
**************************************************/
void poly_tomsg(uint8_t msg[KYBER_INDCPA_MSGBYTES], const poly *a)
{
  unsigned int i,j;
  uint32_t t;

  // For each coefficient we want to decode...
  for(i=0;i<KYBER_N/8;i++) {
    msg[i] = 0;
    for(j=0;j<8;j++) {
      t  = a->coeffs[8*i+j];

      // This math trick checks if the coefficient is closer to 0 or to Q/2.
      // If it's closer to Q/2, the original bit was a 1.
      // If it's closer to 0 (or Q), the original bit was a 0.
      t <<= 1;
      t += 1665;
      t *= 80635;
      t >>= 28;
      t &= 1;
      // Set the corresponding bit in the output message.
      msg[i] |= t << j;
    }
  }
}

/*************************************************
* Name:        poly_getnoise_eta1
*
* Description: Sample a "noise" polynomial.
*              This function generates a polynomial with small random coefficients.
*              This "noise" is crucial for security. We add it to our secret data
*              to hide it, like hiding a whisper in a noisy room.
*              The 'eta1' refers to the size of the noise coefficients.
*
* Arguments:   - poly *r: pointer to the output noise polynomial.
*              - const uint8_t *seed: A random seed to generate the noise from.
*              - uint8_t nonce: A small number to make sure we get different noise
*                               each time, even with the same seed.
**************************************************/
void poly_getnoise_eta1(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce)
{
  // The amount of random data we need depends on the noise parameter ETA1.
  uint8_t buf[KYBER_ETA1*KYBER_N/4];
  // Generate a stream of pseudo-random bytes from the seed and nonce.
  prf(buf, sizeof(buf), seed, nonce);
  // Convert these bytes into a polynomial with small coefficients (the noise).
  poly_cbd_eta1(r, buf);
}

/*************************************************
* Name:        poly_getnoise_eta2
*
* Description: Sample another "noise" polynomial.
*              This is very similar to poly_getnoise_eta1, but it uses a
*              different noise parameter, 'eta2'. Kyber uses two different
*              levels of noise in its calculations.
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *seed: pointer to input seed
*              - uint8_t nonce: one-byte input nonce
**************************************************/
void poly_getnoise_eta2(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce)
{
  uint8_t buf[KYBER_ETA2*KYBER_N/4];
  prf(buf, sizeof(buf), seed, nonce);
  poly_cbd_eta2(r, buf);
}


/*************************************************
* Name:        poly_ntt
*
* Description: Computes the Number-Theoretic Transform (NTT).
*              The NTT is a mathematical shortcut that makes multiplying
*              polynomials super fast. It's like a Fast Fourier Transform (FFT)
*              but for the kind of math we use in Kyber.
*              This function transforms a polynomial into the "NTT domain".
*
* Arguments:   - poly *r: pointer to the polynomial to be transformed.
**************************************************/
void poly_ntt(poly *r)
{
  // This function does the actual NTT calculation.
  ntt(r->coeffs);
  // After the NTT, we need to make sure the coefficients are in the correct range.
  poly_reduce(r);
}

/*************************************************
* Name:        poly_invntt_tomont
*
* Description: Computes the inverse NTT.
*              This function is the reverse of poly_ntt. It takes a polynomial
*              from the "NTT domain" and transforms it back to its normal form.
*              We do this after we're done with our fast multiplication.
*
* Arguments:   - poly *r: pointer to the polynomial to be transformed.
**************************************************/
void poly_invntt_tomont(poly *r)
{
  // This function does the actual inverse NTT calculation.
  invntt(r->coeffs);
}

/*************************************************
* Name:        poly_basemul_montgomery
*
* Description: Multiplies two polynomials that are in the NTT domain.
*              Because they are in the NTT domain, we can just multiply their
*              coefficients one by one, which is much faster than regular
*              polynomial multiplication.
*
* Arguments:   - poly *r: pointer to the output polynomial (the result).
*              - const poly *a: pointer to the first input polynomial.
*              - const poly *b: pointer to the second input polynomial.
**************************************************/
void poly_basemul_montgomery(poly *r, const poly *a, const poly *b)
{
  unsigned int i;
  for(i=0;i<KYBER_N/4;i++) {
    // This 'basemul' function multiplies a small number of coefficients at a time.
    basemul(&r->coeffs[4*i], &a->coeffs[4*i], &b->coeffs[4*i], zetas[64+i]);
    basemul(&r->coeffs[4*i+2], &a->coeffs[4*i+2], &b->coeffs[4*i+2], -zetas[64+i]);
  }
}

/*************************************************
* Name:        poly_tomont
*
* Description: Converts a polynomial to the "Montgomery domain".
*              This is another mathematical trick to make modular multiplication
*              (multiplication where we only care about the remainder) faster.
*              All our fast multiplications happen in this domain.
*
* Arguments:   - poly *r: pointer to the polynomial to be converted.
**************************************************/
void poly_tomont(poly *r)
{
  unsigned int i;
  // A special constant used for Montgomery conversion.
  const int16_t f = (1ULL << 32) % KYBER_Q;
  for(i=0;i<KYBER_N;i++)
    // Convert each coefficient to the Montgomery domain.
    r->coeffs[i] = montgomery_reduce((int32_t)r->coeffs[i]*f);
}

/*************************************************
* Name:        poly_reduce
*
* Description: Applies Barrett reduction to all coefficients of a polynomial.
*              This is a fast way to make sure all our numbers stay within the
*              range [0, KYBER_Q-1]. After adding or subtracting, the numbers
*              can get too big or too small, so we "reduce" them.
*
* Arguments:   - poly *r: pointer to the polynomial to be reduced.
**************************************************/
void poly_reduce(poly *r)
{
  unsigned int i;
  for(i=0;i<KYBER_N;i++)
    r->coeffs[i] = barrett_reduce(r->coeffs[i]);
}

/*************************************************
* Name:        poly_add
*
* Description: Adds two polynomials together.
*              This is done simply by adding their corresponding coefficients.
*
* Arguments: - poly *r: pointer to the output polynomial (a + b).
*            - const poly *a: pointer to the first input polynomial.
*            - const poly *b: pointer to the second input polynomial.
**************************************************/
void poly_add(poly *r, const poly *a, const poly *b)
{
  unsigned int i;
  for(i=0;i<KYBER_N;i++)
    r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}

/*************************************************
* Name:        poly_sub
*
* Description: Subtracts one polynomial from another.
*              This is done by subtracting their corresponding coefficients.
*
* Arguments: - poly *r:       pointer to the output polynomial (a - b).
*            - const poly *a: pointer to the first input polynomial.
*            - const poly *b: pointer to the second input polynomial.
**************************************************/
void poly_sub(poly *r, const poly *a, const poly *b)
{
  unsigned int i;
  for(i=0;i<KYBER_N;i++)
    r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}

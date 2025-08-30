#include <stdint.h>
#include "params.h"
#include "poly.h"
#include "polyvec.h"

/*************************************************
* Name:        polyvec_compress
*
* Description: Compress and serialize a vector of polynomials.
*              A "polyvec" is just a list (vector) of several polynomials.
*              This function takes a list of polynomials and squishes each one
*              to save space, then packs them together.
*
* Arguments:   - uint8_t *r: pointer to the output byte array for the compressed vector.
*              - const polyvec *a: pointer to the input vector of polynomials.
**************************************************/
void polyvec_compress(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES], const polyvec *a)
{
  unsigned int i,j,k;
  uint64_t d0;

  // This compression scheme is for Kyber-1024. It compresses each coefficient to 11 bits.
#if (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 352))
  uint16_t t[8];
  // For each polynomial in the vector...
  for(i=0;i<KYBER_K;i++) {
    // For each chunk of 8 coefficients in the polynomial...
    for(j=0;j<KYBER_N/8;j++) {
      for(k=0;k<8;k++) {
        // Get the coefficient and make sure it's positive.
        t[k]  = a->vec[i].coeffs[8*j+k];
        t[k] += ((int16_t)t[k] >> 15) & KYBER_Q;
        // This is the math trick to squish a 12-bit coefficient down to 11 bits.
        d0 = t[k];
        d0 <<= 11;
        d0 += 1664;
        d0 *= 645084;
        d0 >>= 31;
        t[k] = d0 & 0x7ff;
      }

      // Pack the eight 11-bit values into 11 bytes (8 * 11 = 88 bits = 11 bytes).
      r[ 0] = (t[0] >>  0);
      r[ 1] = (t[0] >>  8) | (t[1] << 3);
      r[ 2] = (t[1] >>  5) | (t[2] << 6);
      r[ 3] = (t[2] >>  2);
      r[ 4] = (t[2] >> 10) | (t[3] << 1);
      r[ 5] = (t[3] >>  7) | (t[4] << 4);
      r[ 6] = (t[4] >>  4) | (t[5] << 7);
      r[ 7] = (t[5] >>  1);
      r[ 8] = (t[5] >>  9) | (t[6] << 2);
      r[ 9] = (t[6] >>  6) | (t[7] << 5);
      r[10] = (t[7] >>  3);
      r += 11;
    }
  }
  // This compression scheme is for Kyber-512 and Kyber-768. It compresses each coefficient to 10 bits.
#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 320))
  uint16_t t[4];
  // For each polynomial in the vector...
  for(i=0;i<KYBER_K;i++) {
    // For each chunk of 4 coefficients in the polynomial...
    for(j=0;j<KYBER_N/4;j++) {
      for(k=0;k<4;k++) {
        // Get the coefficient and make sure it's positive.
        t[k]  = a->vec[i].coeffs[4*j+k];
        t[k] += ((int16_t)t[k] >> 15) & KYBER_Q;
        // This is the math trick to squish a 12-bit coefficient down to 10 bits.
        d0 = t[k];
        d0 <<= 10;
        d0 += 1665;
        d0 *= 1290167;
        d0 >>= 32;
        t[k] = d0 & 0x3ff;
      }

      // Pack the four 10-bit values into 5 bytes (4 * 10 = 40 bits = 5 bytes).
      r[0] = (t[0] >> 0);
      r[1] = (t[0] >> 8) | (t[1] << 2);
      r[2] = (t[1] >> 6) | (t[2] << 4);
      r[3] = (t[2] >> 4) | (t[3] << 6);
      r[4] = (t[3] >> 2);
      r += 5;
    }
  }
#else
#error "KYBER_POLYVECCOMPRESSEDBYTES must be in {320*KYBER_K, 352*KYBER_K}"
#endif
}

/*************************************************
* Name:        polyvec_decompress
*
* Description: De-serialize and decompress a vector of polynomials.
*              This is the reverse of polyvec_compress. It takes a compressed
*              byte array and unpacks it back into a full vector of polynomials.
*
* Arguments:   - polyvec *r:       pointer to the output vector of polynomials.
*              - const uint8_t *a: pointer to the input byte array.
**************************************************/
void polyvec_decompress(polyvec *r, const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES])
{
  unsigned int i,j,k;

#if (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 352))
  uint16_t t[8];
  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_N/8;j++) {
      // Unpack 11 bytes back into eight 11-bit values.
      t[0] = (a[0] >> 0) | ((uint16_t)a[ 1] << 8);
      t[1] = (a[1] >> 3) | ((uint16_t)a[ 2] << 5);
      t[2] = (a[2] >> 6) | ((uint16_t)a[ 3] << 2) | ((uint16_t)a[4] << 10);
      t[3] = (a[4] >> 1) | ((uint16_t)a[ 5] << 7);
      t[4] = (a[5] >> 4) | ((uint16_t)a[ 6] << 4);
      t[5] = (a[6] >> 7) | ((uint16_t)a[ 7] << 1) | ((uint16_t)a[8] << 9);
      t[6] = (a[8] >> 2) | ((uint16_t)a[ 9] << 6);
      t[7] = (a[9] >> 5) | ((uint16_t)a[10] << 3);
      a += 11;

      // For each 11-bit value, scale it back up to an approximate 12-bit coefficient.
      for(k=0;k<8;k++)
        r->vec[i].coeffs[8*j+k] = ((uint32_t)(t[k] & 0x7FF)*KYBER_Q + 1024) >> 11;
    }
  }
#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 320))
  uint16_t t[4];
  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_N/4;j++) {
      // Unpack 5 bytes back into four 10-bit values.
      t[0] = (a[0] >> 0) | ((uint16_t)a[1] << 8);
      t[1] = (a[1] >> 2) | ((uint16_t)a[2] << 6);
      t[2] = (a[2] >> 4) | ((uint16_t)a[3] << 4);
      t[3] = (a[3] >> 6) | ((uint16_t)a[4] << 2);
      a += 5;

      // For each 10-bit value, scale it back up to an approximate 12-bit coefficient.
      for(k=0;k<4;k++)
        r->vec[i].coeffs[4*j+k] = ((uint32_t)(t[k] & 0x3FF)*KYBER_Q + 512) >> 10;
    }
  }
#else
#error "KYBER_POLYVECCOMPRESSEDBYTES needs to be in {320*KYBER_K, 352*KYBER_K}"
#endif
}

/*************************************************
* Name:        polyvec_tobytes
*
* Description: Serialize a vector of polynomials into a byte array (without compression).
*              This function just calls the `poly_tobytes` function for each
*              polynomial in the vector, one after the other.
*
* Arguments:   - uint8_t *r: pointer to the output byte array.
*              - const polyvec *a: pointer to the input vector of polynomials.
**************************************************/
void polyvec_tobytes(uint8_t r[KYBER_POLYVECBYTES], const polyvec *a)
{
  unsigned int i;
  for(i=0;i<KYBER_K;i++)
    poly_tobytes(r+i*KYBER_POLYBYTES, &a->vec[i]);
}

/*************************************************
* Name:        polyvec_frombytes
*
* Description: De-serialize a byte array into a vector of polynomials.
*              This is the reverse of `polyvec_tobytes`. It reconstructs the
*              vector of polynomials from the byte array.
*
* Arguments:   - polyvec *r:       pointer to the output vector of polynomials.
*              - const uint8_t *a: pointer to the input byte array.
**************************************************/
void polyvec_frombytes(polyvec *r, const uint8_t a[KYBER_POLYVECBYTES])
{
  unsigned int i;
  for(i=0;i<KYBER_K;i++)
    poly_frombytes(&r->vec[i], a+i*KYBER_POLYBYTES);
}

/*************************************************
* Name:        polyvec_ntt
*
* Description: Apply the forward NTT to all polynomials in a vector.
*              This gets the whole vector ready for fast multiplication.
*
* Arguments:   - polyvec *r: pointer to the vector of polynomials to transform.
**************************************************/
void polyvec_ntt(polyvec *r)
{
  unsigned int i;
  for(i=0;i<KYBER_K;i++)
    poly_ntt(&r->vec[i]);
}

/*************************************************
* Name:        polyvec_invntt_tomont
*
* Description: Apply the inverse NTT to all polynomials in a vector.
*              This brings the polynomials back from the NTT domain to the
*              normal domain after multiplication is done.
*
* Arguments:   - polyvec *r: pointer to the vector of polynomials to transform.
**************************************************/
void polyvec_invntt_tomont(polyvec *r)
{
  unsigned int i;
  for(i=0;i<KYBER_K;i++)
    poly_invntt_tomont(&r->vec[i]);
}

/*************************************************
* Name:        polyvec_basemul_acc_montgomery
*
* Description: This is a core operation! It computes the "dot product" of two
*              polynomial vectors. If you have two vectors a=[a1, a2] and
*              b=[b1, b2], the dot product is (a1*b1 + a2*b2). This function
*              does the same, but with polynomials.
*              It multiplies the corresponding polynomials from vectors 'a' and 'b'
*              and accumulates (adds) the results into a single output polynomial 'r'.
*
* Arguments: - poly *r: pointer to the output polynomial (the result of the dot product).
*            - const polyvec *a: pointer to the first input vector.
*            - const polyvec *b: pointer to the second input vector.
**************************************************/
void polyvec_basemul_acc_montgomery(poly *r, const polyvec *a, const polyvec *b)
{
  unsigned int i;
  poly t;

  // Multiply the first pair of polynomials and store it in 'r'.
  poly_basemul_montgomery(r, &a->vec[0], &b->vec[0]);
  // For the rest of the pairs...
  for(i=1;i<KYBER_K;i++) {
    // Multiply the next pair of polynomials and store it in a temporary poly 't'.
    poly_basemul_montgomery(&t, &a->vec[i], &b->vec[i]);
    // Add the temporary result to our accumulator 'r'.
    poly_add(r, r, &t);
  }

  // Make sure the final coefficients are in the correct range.
  poly_reduce(r);
}

/*************************************************
* Name:        polyvec_reduce
*
* Description: Applies Barrett reduction to each coefficient of each polynomial
*              in the vector. This is just a housekeeping function to keep all
*              the numbers in their correct range after operations like addition.
*
* Arguments:   - polyvec *r: pointer to the vector of polynomials to be reduced.
**************************************************/
void polyvec_reduce(polyvec *r)
{
  unsigned int i;
  for(i=0;i<KYBER_K;i++)
    poly_reduce(&r->vec[i]);
}

/*************************************************
* Name:        polyvec_add
*
* Description: Adds two vectors of polynomials together.
*              This works "element-wise", meaning it adds the first polynomial of
*              vector 'a' to the first of vector 'b', the second to the second, and so on.
*
* Arguments: - polyvec *r: pointer to the output vector (a + b).
*            - const polyvec *a: pointer to the first input vector.
*            - const polyvec *b: pointer to the second input vector.
**************************************************/
void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b)
{
  unsigned int i;
  for(i=0;i<KYBER_K;i++)
    poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
}

/*
  This file is part of ethash.

  ethash is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  ethash is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with cpp-ethereum.  If not, see <http://www.gnu.org/licenses/>.
*/
/** @file internal.c
* @author Tim Hughes <tim@twistedfury.com>
* @author Matthew Wampler-Doty
* @date 2015
*/

#include <assert.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stddef.h>

/*
 * BEGIN code from all headers
 */

 #define MIX_BYTES 128
 #define HASH_BYTES 64
 #define DATASET_PARENTS 256
 #define CACHE_ROUNDS 3
 #define ACCESSES 64

 /*
  * BEGIN from fnv.h
  */

 #define FNV_PRIME 0x01000193

 static inline uint32_t fnv_hash(const uint32_t x, const uint32_t y) {
 	return x*FNV_PRIME ^ y;
 }

 /*
  * END from fnv.h
  */

 /*
  * BEGIN from sha3.h
  */

 #define decsha3(bits) \
   int sha3_##bits(uint8_t*, size_t, const uint8_t*, size_t);

 decsha3(256)
 decsha3(512)

 static inline void SHA3_256(uint8_t * const ret, uint8_t const *data, const size_t size) {
     sha3_256(ret, 32, data, size);
 }

 static inline void SHA3_512(uint8_t * const ret, uint8_t const *data, const size_t size) {
     sha3_512(ret, 64, data, size);
 }

 /*
  * END from sha3.h
  */

  /*
   * BEGIN from internal.h
   */

   // compile time settings
   #define NODE_WORDS (64/4)
   #define MIX_WORDS (MIX_BYTES/4)
   #define MIX_NODES (MIX_WORDS / NODE_WORDS)
   #include <stdint.h>

   typedef union node {
       uint8_t bytes[NODE_WORDS * 4];
       uint32_t words[NODE_WORDS];
       uint64_t double_words[NODE_WORDS / 2];
   } node;

   /*
    * END from internal.h
    */

 typedef struct ethash_params {
     size_t full_size;               // Size of full data set (in bytes, multiple of mix size (128)).
     size_t cache_size;              // Size of compute cache (in bytes, multiple of node size (64)).
 } ethash_params;

 typedef struct ethash_return_value {
     uint8_t result[32];
     uint8_t mix_hash[32];
 } ethash_return_value;

 /*
  * END code from all headers
  */

/*
 * BEGIN from sha3.c
 */

 /******** The Keccak-f[1600] permutation ********/

 /*** Constants. ***/
 static const uint8_t rho[24] = \
   { 1,  3,   6, 10, 15, 21,
         28, 36, 45, 55,  2, 14,
         27, 41, 56,  8, 25, 43,
         62, 18, 39, 61, 20, 44};
 static const uint8_t pi[24] = \
   {10,  7, 11, 17, 18, 3,
         5, 16,  8, 21, 24, 4,
         15, 23, 19, 13, 12, 2,
         20, 14, 22,  9, 6,  1};
 static const uint64_t RC[24] = \
   {1ULL, 0x8082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
         0x808bULL, 0x80000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
         0x8aULL, 0x88ULL, 0x80008009ULL, 0x8000000aULL,
         0x8000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
         0x8000000000008002ULL, 0x8000000000000080ULL, 0x800aULL, 0x800000008000000aULL,
         0x8000000080008081ULL, 0x8000000000008080ULL, 0x80000001ULL, 0x8000000080008008ULL};

 /*** Helper macros to unroll the permutation. ***/
 #define rol(x, s) (((x) << s) | ((x) >> (64 - s)))
 #define REPEAT6(e) e e e e e e
 #define REPEAT24(e) REPEAT6(e e e e)
 #define REPEAT5(e) e e e e e
 #define FOR5(v, s, e) \
   v = 0;            \
   REPEAT5(e; v += s;)

 /*** Keccak-f[1600] ***/
 static inline void keccakf(void* state) {
     uint64_t* a = (uint64_t*)state;
     uint64_t b[5] = {0};
     uint64_t t = 0;
     uint8_t x, y;

     for (int i = 0; i < 24; i++) {
         // Theta
         FOR5(x, 1,
                 b[x] = 0;
                 FOR5(y, 5,
                         b[x] ^= a[x + y]; ))
         FOR5(x, 1,
                 FOR5(y, 5,
                         a[y + x] ^= b[(x + 4) % 5] ^ rol(b[(x + 1) % 5], 1); ))
         // Rho and pi
         t = a[1];
         x = 0;
         REPEAT24(b[0] = a[pi[x]];
                 a[pi[x]] = rol(t, rho[x]);
                 t = b[0];
                 x++; )
         // Chi
         FOR5(y,
                 5,
                 FOR5(x, 1,
                         b[x] = a[y + x];)
                 FOR5(x, 1,
                 a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]); ))
         // Iota
         a[0] ^= RC[i];
     }
 }

 /******** The FIPS202-defined functions. ********/

 /*** Some helper macros. ***/

 #define _(S) do { S } while (0)
 #define FOR(i, ST, L, S) \
   _(for (size_t i = 0; i < L; i += ST) { S; })
 #define mkapply_ds(NAME, S)                                          \
   static inline void NAME(uint8_t* dst,                              \
                           const uint8_t* src,                        \
                           size_t len) {                              \
     FOR(i, 1, len, S);                                               \
   }
 #define mkapply_sd(NAME, S)                                          \
   static inline void NAME(const uint8_t* src,                        \
                           uint8_t* dst,                              \
                           size_t len) {                              \
     FOR(i, 1, len, S);                                               \
   }

 mkapply_ds(xorin, dst[i] ^= src[i])  // xorin
 mkapply_sd(setout, dst[i] = src[i])  // setout

 #define P keccakf
 #define Plen 200

 // Fold P*F over the full blocks of an input.
 #define foldP(I, L, F) \
   while (L >= rate) {  \
     F(a, I, rate);     \
     P(a);              \
     I += rate;         \
     L -= rate;         \
   }

 /** The sponge-based hash construction. **/
 static inline int hash(uint8_t* out, size_t outlen,
         const uint8_t* in, size_t inlen,
         size_t rate, uint8_t delim) {
     if ((out == NULL) || ((in == NULL) && inlen != 0) || (rate >= Plen)) {
         return -1;
     }
     uint8_t a[Plen] = {0};
     // Absorb input.
     foldP(in, inlen, xorin);
     // Xor in the DS and pad frame.
     a[inlen] ^= delim;
     a[rate - 1] ^= 0x80;
     // Xor in the last block.
     xorin(a, in, inlen);
     // Apply P
     P(a);
     // Squeeze output.
     foldP(out, outlen, setout);
     setout(a, out, outlen);
     memset(a, 0, 200);
     return 0;
 }

 #define defsha3(bits)                                             \
   int sha3_##bits(uint8_t* out, size_t outlen,                    \
                   const uint8_t* in, size_t inlen) {              \
     if (outlen > (bits/8)) {                                      \
       return -1;                                                  \
     }                                                             \
     return hash(out, outlen, in, inlen, 200 - (bits / 4), 0x01);  \
   }

 /*** FIPS202 SHA3 FOFs ***/
 defsha3(256)
 defsha3(512)

 /*
  * END from sha3.c
  */

void ethash_hash(
        ethash_return_value *ret,
        node const *full_nodes,
        ethash_params const *params,
        const uint8_t header_hash[32],
        const uint64_t nonce) {

    assert((params->full_size % MIX_WORDS) == 0);

    // pack hash and nonce together into first 40 bytes of s_mix
    assert(sizeof(node) * 8 == 512);
    node s_mix[MIX_NODES + 1];
    memcpy(s_mix[0].bytes, header_hash, 32);

    s_mix[0].double_words[4] = nonce;

    // compute sha3-512 hash and replicate across mix
    SHA3_512(s_mix->bytes, s_mix->bytes, 40);

    node *const mix = s_mix + 1;
    for (unsigned w = 0; w != MIX_WORDS; ++w) {
        mix->words[w] = s_mix[0].words[w % NODE_WORDS];
    }

    unsigned const
            page_size = sizeof(uint32_t) * MIX_WORDS,
            num_full_pages = (unsigned) (params->full_size / page_size);

    for (unsigned i = 0; i != ACCESSES; ++i) {
        uint32_t const index = ((s_mix->words[0] ^ i) * FNV_PRIME ^ mix->words[i % MIX_WORDS]) % num_full_pages;

        for (unsigned n = 0; n != MIX_NODES; ++n) {
            const node *dag_node = &full_nodes[MIX_NODES * index + n];

            for (unsigned w = 0; w != NODE_WORDS; ++w) {
                mix[n].words[w] = fnv_hash(mix[n].words[w], dag_node->words[w]);
            }
        }
    }

    // compress mix
    for (unsigned w = 0; w != MIX_WORDS; w += 4) {
        uint32_t reduction = mix->words[w + 0];
        reduction = reduction * FNV_PRIME ^ mix->words[w + 1];
        reduction = reduction * FNV_PRIME ^ mix->words[w + 2];
        reduction = reduction * FNV_PRIME ^ mix->words[w + 3];
        mix->words[w / 4] = reduction;
    }

    memcpy(ret->mix_hash, mix->bytes, 32);
    // final Keccak hash
    SHA3_256(ret->result, s_mix->bytes, 64 + 32); // Keccak-256(s + compressed_mix)
}

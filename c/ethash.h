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
  along with ethash.  If not, see <http://www.gnu.org/licenses/>.
*/

/** @file ethash.h
* @date 2015
*/
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stddef.h>

#define REVISION 23
#define DATASET_BYTES_INIT 1073741824U // 2**30
#define DATASET_BYTES_GROWTH 8388608U  // 2**23
#define CACHE_BYTES_INIT 1073741824U // 2**24
#define CACHE_BYTES_GROWTH 131072U  // 2**17
#define EPOCH_LENGTH 30000U
#define MIX_BYTES 128
#define HASH_BYTES 64
#define DATASET_PARENTS 256
#define CACHE_ROUNDS 3
#define ACCESSES 64

#ifdef __cplusplus
extern "C" {
#endif

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

  #if defined(_M_X64) && ENABLE_SSE
  	__m128i xmm[NODE_WORDS/4];
  #endif

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

void ethash_hash(ethash_return_value *ret, node const *full_nodes, ethash_params const *params, const uint8_t header_hash[32], const uint64_t nonce);

#ifdef __cplusplus
}
#endif

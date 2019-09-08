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
#include "ethash.h"
#include "fnv.h"
#include "endian.h"
#include "internal.h"
#include "data_sizes.h"
#include "sha3.h"

static void ethash_hash(
        ethash_return_value *ret,
        node const *full_nodes,
        ethash_cache const *cache,
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

void ethash_full(ethash_return_value *ret, void const *full_mem, ethash_params const *params, const uint8_t previous_hash[32], const uint64_t nonce) {
    ethash_hash(ret, (node const *) full_mem, NULL, params, previous_hash, nonce);
}

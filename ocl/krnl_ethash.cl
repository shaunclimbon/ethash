//------------------------------------------------------------------------------
//
// kernel:  ethash
//
// Purpose: Demonstrate Ethereum Ethash in OpenCL for FPGA
//

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

static inline uint fnv_hash(const uint x, const uint y) {
	return x*FNV_PRIME ^ y;
}

/*
 * END from fnv.h
 */

/*
 * BEGIN from sha3.h
 */

#define decsha3(bits) \
		int sha3_##bits(uchar*, size_t, const uchar*, size_t);

decsha3(256)
decsha3(512)

static inline void SHA3_256(uchar * const ret, uchar const *data, const size_t size) {
	sha3_256(ret, 32, data, size);
}

static inline void SHA3_512(uchar * const ret, uchar const *data, const size_t size) {
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

/*
 * END from internal.h
 */

/*
 * END code from all headers
 */

/*
 * BEGIN from sha3.c
 */

/******** The Keccak-f[1600] permutation ********/

/*** Constants. ***/
constant const uchar rho[24] = \
		{ 1,  3,   6, 10, 15, 21,
	28, 36, 45, 55,  2, 14,
	27, 41, 56,  8, 25, 43,
	62, 18, 39, 61, 20, 44};
constant const uchar pi[24] = \
		{10,  7, 11, 17, 18, 3,
	5, 16,  8, 21, 24, 4,
	15, 23, 19, 13, 12, 2,
	20, 14, 22,  9, 6,  1};
constant const ulong RC[24] = \
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
void keccakf(void* state) {
	ulong* a = (ulong*)state;
	ulong b[5] = {0};
	ulong t = 0;
	uchar x, y;

	keccak: for (int i = 0; i < 24; i++) {
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
		static inline void NAME(uchar* dst,                              \
				const uchar* src,                        \
				size_t len) {                              \
	FOR(i, 1, len, S);                                               \
}
#define mkapply_sd(NAME, S)                                          \
		static inline void NAME(const uchar* src,                        \
				uchar* dst,                              \
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
int hash(uchar* out, size_t outlen,
		const uchar* in, size_t inlen,
		size_t rate, uchar delim) {
	uchar a[Plen] = {0};
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
	//memset(a, 0, 200);
	hash: for (int i = 0; i < 200; i++) {
		a[i] = 0;
	}
	return 0;
}

#define defsha3(bits)                                             \
		int sha3_##bits(uchar* out, size_t outlen,                    \
				const uchar* in, size_t inlen) {              \
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

#define DAG_SIZE 1073739904U

typedef union
{
	uchar bytes[32 / sizeof(uchar)];
	uint words[32 / sizeof(uint)];
	ulong double_words[32 / sizeof(ulong)];
} hash32_t;

typedef union
{
	uchar bytes[NODE_WORDS * 4];
	uint words[NODE_WORDS];
	ulong double_words[NODE_WORDS / 2];
} node64_t;

static void start_mix(const global hash32_t* header_hash, node64_t* seed, node64_t* mix, const uint nonce)
{
	//node64_t* mix = s_mix + 1;

	//memcpy(s_mix[0].bytes, header_hash, 32);
	ld_hdr: for (int i = 0; i < 32/4; i++) {
		//s_mix[0].words[i] = header_hash->words[i];
		seed->words[i] = header_hash->words[i];
	}

	//s_mix[0].double_words[4] = nonce;
	seed->double_words[4] = nonce;

	// compute sha3-512 hash and replicate across mix
	SHA3_512(seed->bytes, seed->bytes, 40);

	mix: for (unsigned w = 0; w != MIX_WORDS; ++w) {
		mix->words[w] = seed->words[w % NODE_WORDS];
	}
}

static void proc_dag(global node64_t* full_nodes, node64_t* seed, node64_t* mix)
{
	//node64_t* mix = s_mix + 1;
	unsigned const full_size = (unsigned) DAG_SIZE;
	unsigned const num_full_pages = (unsigned) (full_size / MIX_BYTES);
	uint index;
	node64_t dag_node[MIX_NODES];

	outer: for (unsigned i = 0; i != ACCESSES; ++i) {
		index = ((seed->words[0] ^ i) * FNV_PRIME ^ mix->words[i % MIX_WORDS]) % num_full_pages;

		middle1: for (unsigned n = 0; n != MIX_NODES; ++n) {
			dag_node[n] = full_nodes[MIX_NODES * index + n];
		}

		__attribute__((opencl_unroll_hint))
		middle2: for (unsigned n = 0; n != MIX_NODES; ++n) {
			__attribute__((opencl_unroll_hint))
			inner: for (unsigned w = 0; w != NODE_WORDS; ++w) {
				mix[n].words[w] = fnv_hash(mix[n].words[w], dag_node[n].words[w]);
			}
		}
	}

	// compress mix (length reduced from 128 to 32 bytes)
	compress: for (unsigned w = 0; w != MIX_WORDS; w += 4) {
		uint reduction = mix->words[w + 0];
		reduction = reduction * FNV_PRIME ^ mix->words[w + 1];
		reduction = reduction * FNV_PRIME ^ mix->words[w + 2];
		reduction = reduction * FNV_PRIME ^ mix->words[w + 3];
		mix->words[w / 4] = reduction;
	}
}

static void calc_ret(global hash32_t* ret_mix, global hash32_t* ret_hash, node64_t* seed, node64_t* s_mix)
{
	node64_t* mix = s_mix + 1;
	hash32_t hash;

	//cpy seed to s_mix
	s_mix: for (unsigned i = 0; i < 64/4; i++) {
		s_mix->words[i] = seed->words[i];
	}

	//memcpy(ret_mix, mix->bytes, 32);
	st_mix: for (unsigned i = 0; i < 32/4; i++) {
		ret_mix->words[i] = mix->words[i];
	}
	// final Keccak hash
	SHA3_256(hash.bytes, s_mix->bytes, 64 + 32); // Keccak-256(s + compressed_mix)
	// copy from local mem to global
	st_hsh: for (unsigned i = 0; i < 32/4; i++) {
		ret_hash->words[i] = hash.words[i];
	}
}

kernel __attribute__((reqd_work_group_size(1, 1, 1)))
//__attribute__ ((xcl_dataflow))
void krnl_ethash(
		global hash32_t* ret_mix,
		global hash32_t* ret_hash, // s+mix
		global node64_t* full_nodes, // dag
		const global hash32_t* header_hash,
		const uint nonce)
{
	node64_t s_mix[MIX_NODES + 1];
	node64_t seed;
	node64_t* mix = s_mix + 1;

	start_mix(header_hash, &seed, mix, nonce);

	proc_dag(full_nodes, &seed, mix);

	calc_ret(ret_mix, ret_hash, &seed, s_mix);
}

// Copyright (c) 2017 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ethereum.h"
#include "endian.h"
#include "sha3_ethash.h"
#include "BlockHeader.h"

using namespace dev;
using namespace eth;

#define ETHASH_EPOCH_LENGTH 30000U

enum { MixHashField = 0, NonceField = 1 };

using Nonce = h64;

/// Type of a seedhash/blockhash e.t.c.
typedef struct ethash_h256 { uint8_t b[32]; } ethash_h256_t;

void ethash_quick_hash(
	ethash_h256_t* return_hash,
	ethash_h256_t const* header_hash,
	uint64_t const nonce,
	ethash_h256_t const* mix_hash
)
{
	uint8_t buf[64 + 32];
	memcpy(buf, header_hash, 32);
	fix_endian64_same(nonce);
	memcpy(&(buf[32]), &nonce, 8);
	SHA3_512(buf, buf, 40);
	memcpy(&(buf[64]), mix_hash, 32);
	SHA3_256(return_hash, buf, 64 + 32);
}

uint8_t ethash_h256_get(ethash_h256_t const* hash, unsigned int i)
{
	return hash->b[i];
}

bool ethash_check_difficulty(
	ethash_h256_t const* hash,
	ethash_h256_t const* boundary
)
{
	// Boundary is big endian
	for (int i = 0; i < 32; i++) {
		if (ethash_h256_get(hash, i) == ethash_h256_get(boundary, i)) {
			continue;
		}
		return ethash_h256_get(hash, i) < ethash_h256_get(boundary, i);
	}
	return true;
}

bool ethash_quick_check_difficulty(
	ethash_h256_t const* header_hash,
	uint64_t const nonce,
	ethash_h256_t const* mix_hash,
	ethash_h256_t const* boundary
)
{
	ethash_h256_t return_hash;
	ethash_quick_hash(&return_hash, header_hash, nonce, mix_hash);
	return ethash_check_difficulty(&return_hash, boundary);
}


bool quickVerifySeal(BlockHeader const& _bi)
{
	if (_bi.number() >= ETHASH_EPOCH_LENGTH * 2048)
		return false;

	auto h = _bi.hash(WithoutSeal);
	auto m = _bi.seal<h256>(MixHashField); // mixHash(_bi);
	auto n = _bi.seal<Nonce>(NonceField); // nonce(_bi);
        auto d = _bi.difficulty();
	auto b = d ? (h256)u256((bigint(1) << 256) / d) : h256(); // boundary(_bi);
	bool ret = !!ethash_quick_check_difficulty(
		(ethash_h256_t const*)h.data(),
		(uint64_t)(u64)n,
		(ethash_h256_t const*)m.data(),
		(ethash_h256_t const*)b.data());
	return ret;
}


bool VerifyHeader(const std::vector<unsigned char>& data) {
    BlockHeader header(data, BlockDataType::HeaderData);
    return quickVerifySeal(header);
}

// Copyright (c) 2017 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ethereum.h"
#include "endian.h"
#include "ethash.h"
#include "ethash_internal.h"
#include "ethash_sha3.h"
#include "BlockHeader.h"

using namespace dev;
using namespace eth;

#define ETHASH_EPOCH_LENGTH 30000U

enum { MixHashField = 0, NonceField = 1 };

using Nonce = h64;

struct Result
{
        h256 value;
        h256 mixHash;
        bool success;
};

static Nonce nonce(BlockHeader const& _bi)
{
        return _bi.seal<Nonce>(NonceField);
}

static h256 mixHash(BlockHeader const& _bi)
{
        return _bi.seal<h256>(MixHashField);
}

static h256 boundary(BlockHeader const& _bi)
{
        auto d = _bi.difficulty();
        return d ? (h256)u256((bigint(1) << 256) / d) : h256();
}

h256 seedHash(BlockHeader const& _bi)
{
        unsigned _number = (unsigned)_bi.number();
        unsigned epoch = _number / ETHASH_EPOCH_LENGTH;
        h256 ret;
        unsigned n = 0;
        for (; n < epoch; ++n, ret = sha3(ret)) {}
        return ret;
}

uint64_t EthashAux_number(h256 const& _seedHash)
{
        unsigned epoch = 0;
        for (h256 h; h != _seedHash && epoch < 2048; ++epoch, h = sha3(h)) {}
        return epoch * ETHASH_EPOCH_LENGTH;
}

bool quickVerifySeal(BlockHeader const& _bi)
{
        if (_bi.number() >= ETHASH_EPOCH_LENGTH * 2048)
                return false;
        auto h = _bi.hash(WithoutSeal);
        auto m = mixHash(_bi);
        auto n = nonce(_bi);
        auto b = boundary(_bi);
        bool ret = !!ethash_quick_check_difficulty(
                (ethash_h256_t const*)h.data(),
                (uint64_t)(u64)n,
                (ethash_h256_t const*)m.data(),
                (ethash_h256_t const*)b.data());
        return ret;
}

Result EthashAux_eval(h256 const& _seedHash, h256 const& _headerHash, Nonce const& _nonce)
{
        uint64_t blockNumber = EthashAux_number(_seedHash);
        ethash_light_t light = ethash_light_new(blockNumber);
        uint64_t size = ethash_get_cachesize(blockNumber);
        ethash_return_value r = ethash_light_compute(light, *(ethash_h256_t*)_headerHash.data(), (uint64_t)(u64)_nonce);
        if (r.success) {
                return Result{h256((uint8_t*)&r.result, h256::ConstructFromPointer), h256((uint8_t*)&r.mix_hash, h256::ConstructFromPointer), true};
        }
        return Result{~h256(), h256(), false};
}

bool verifySeal(BlockHeader const& _bi)
{
        bool pre = quickVerifySeal(_bi);
        if (!pre) return false;
        auto result = EthashAux_eval(seedHash(_bi), _bi.hash(WithoutSeal), nonce(_bi));
        bool slow = result.value <= boundary(_bi) && result.mixHash == mixHash(_bi);
        return slow;
}

bool VerifyHeader(const std::vector<unsigned char>& data) {
        BlockHeader header(data, BlockDataType::HeaderData);
        return verifySeal(header);
}

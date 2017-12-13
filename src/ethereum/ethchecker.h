// Copyright (c) 2017 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ETHEREUM_ETHCACHE_H
#define BITCOIN_ETHEREUM_ETHCACHE_H

#include "script/sigcache.h"

#include <vector>

class CPubKey;

class EthCachingTransactionSignatureChecker : public CachingTransactionSignatureChecker
{
public:
    EthCachingTransactionSignatureChecker(const CTransaction* txToIn, unsigned int nInIn, bool storeIn=true) : CachingTransactionSignatureChecker(txToIn, nInIn, storeIn) {}

    bool CheckEthHeader(const std::vector<unsigned char>& header) const;
};

#endif // BITCOIN_ETHEREUM_ETHCACHE_H

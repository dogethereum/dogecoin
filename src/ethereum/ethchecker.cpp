// Copyright (c) 2017 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ethereum/ethchecker.h"
#include "ethereum/ethereum.h"

bool EthCachingTransactionSignatureChecker::CheckEthHeader(const std::vector<unsigned char>& header) const {
    return VerifyHeader(header);
}

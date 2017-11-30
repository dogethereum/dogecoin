// Copyright (c) 2017 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ethereum.h"
#include "BlockHeader.h"

using namespace dev;
using namespace eth;

bool VerifyHeader(const std::vector<unsigned char>& data) {
    BlockHeader header(data);
    return true;
}

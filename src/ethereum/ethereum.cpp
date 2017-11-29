// Copyright (c) 2017 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ethereum.h"
#include "RLP.h"

using namespace dev;

struct EthBlockHeader {
    h256 m_parentHash;
    h256 m_sha3Uncles;
    h160 m_author;
    h256 m_stateRoot;
    h256 m_transactionsRoot;
    h256 m_receiptsRoot;
    h2048 m_logBloom;
    u256 m_difficulty;
    u256 m_number;
    u256 m_gasLimit;
    u256 m_gasUsed;
    u256 m_timestamp;
    bytes m_extraData;
    std::vector<bytes> m_seal;
};

EthBlockHeader parseEthBlockHeader(const std::vector<unsigned char>& data) {
    EthBlockHeader header;
    RLP parser = RLP(data);
    header.m_parentHash = parser[0].toHash<h256>(RLP::VeryStrict);
    header.m_sha3Uncles = parser[1].toHash<h256>(RLP::VeryStrict);
    header.m_author = parser[2].toHash<h160>(RLP::VeryStrict);
    header.m_stateRoot = parser[3].toHash<h256>(RLP::VeryStrict);
    header.m_transactionsRoot = parser[4].toHash<h256>(RLP::VeryStrict);
    header.m_receiptsRoot = parser[5].toHash<h256>(RLP::VeryStrict);
    header.m_logBloom = parser[6].toHash<h2048>(RLP::VeryStrict);
    header.m_difficulty = parser[7].toInt<u256>();
    header.m_number = parser[8].toInt<u256>();
    header.m_gasLimit = parser[9].toInt<u256>();
    header.m_gasUsed = parser[10].toInt<u256>();
    header.m_timestamp = parser[11].toInt<u256>();
    header.m_extraData = parser[12].toBytes();
    header.m_seal.clear();
    for (unsigned i = 13; i < parser.itemCount(); ++i)
            header.m_seal.push_back(parser[i].data().toBytes());
    return header;
}

bool VerifyHeader(const std::vector<unsigned char>& data) {
    EthBlockHeader header = parseEthBlockHeader(data);
    return true;
}

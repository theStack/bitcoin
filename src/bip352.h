// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BIP352_H
#define BITCOIN_BIP352_H

#include <key.h>
#include <pubkey.h>
#include <primitives/transaction.h>
#include <uint256.h>

#include <array>
#include <vector>

namespace BIP352 {

using InputPrivkeysTweak = std::array<unsigned char, 32>;
using InputPubkeysTweak = std::array<unsigned char, 33>;
using SharedSecret = std::array<unsigned char, 33>;

// Silent Payments sender interface
InputPrivkeysTweak CreateInputPrivkeysTweak(
    const std::vector<CKey>& plain_keys,
    const std::vector<CKey>& taproot_keys,
    const uint256& outpoints_hash);

SharedSecret CreateSharedSecretSender(
    const InputPrivkeysTweak& privkeys_tweak,
    const CPubKey& receiver_scan_pubkey);

// Silent Payments receiver interface
InputPubkeysTweak CreateInputPubkeysTweak(
    const std::vector<CPubKey>& plain_pubkeys,
    const std::vector<XOnlyPubKey>& taproot_pubkeys,
    const uint256& outpoints_hash);

SharedSecret CreateSharedSecretReceiver(
    const InputPubkeysTweak& pubkeys_tweak,
    const CKey& receiver_scan_privkey);

// Silent Payments common interface
uint256 HashOutpoints(const std::vector<COutPoint>& tx_outpoints);
XOnlyPubKey CreateOutput(
    const SharedSecret& shared_secret,
    const CPubKey& receiver_spend_pubkey,
    uint32_t output_index);
}; // namespace BIP352
#endif

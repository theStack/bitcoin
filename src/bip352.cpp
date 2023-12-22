// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bip352.h>

#include <secp256k1_silentpayments.h>
#include <uint256.h>

#include <algorithm>

extern secp256k1_context* secp256k1_context_sign; // TODO: this is hacky, is there a better solution?

namespace BIP352 {

uint256 HashOutpoints(const std::vector<COutPoint>& tx_outpoints)
{
    // Make a local copy of the outpoints so we can sort them before hashing.
    // This is to ensure the sender and receiver deterministically arrive at the same outpoint hash,
    // regardless of how the outpoints are ordered in the transaction.

    std::vector<COutPoint> outpoints{tx_outpoints};
    std::sort(outpoints.begin(), outpoints.end());

    HashWriter h;
    for (const auto& outpoint: outpoints) {
        h << outpoint;
    }
    return h.GetSHA256();
}

InputPrivkeysTweak CreateInputPrivkeysTweak(
    const std::vector<CKey>& plain_keys,
    const std::vector<CKey>& taproot_keys,
    const uint256& outpoints_hash)
{
    InputPrivkeysTweak result_tweak;
    std::vector<unsigned char> plain_keys_buf(plain_keys.size()*32);
    std::vector<unsigned char> taproot_keys_buf(taproot_keys.size()*32);

    for (size_t i = 0; i < plain_keys.size(); i++) {
        std::copy(plain_keys[i].begin(), plain_keys[i].end(), plain_keys_buf.data() + i*32);
    }
    for (size_t i = 0; i < taproot_keys.size(); i++) {
        std::copy(taproot_keys[i].begin(), taproot_keys[i].end(), taproot_keys_buf.data() + i*32);
    }

    bool ret = secp256k1_silentpayments_create_private_tweak_data(secp256k1_context_sign, result_tweak.data(),
        plain_keys_buf.data(), plain_keys.size(), taproot_keys_buf.data(), taproot_keys.size(), outpoints_hash.data());
    assert(ret);

    return result_tweak;
}

SharedSecret CreateSharedSecretSender(
    const InputPrivkeysTweak& privkeys_tweak,
    const CPubKey& receiver_scan_pubkey)
{
    SharedSecret result_ss;
    secp256k1_pubkey scan_pubkey_obj;

    bool ret = secp256k1_ec_pubkey_parse(secp256k1_context_static, &scan_pubkey_obj,
        receiver_scan_pubkey.data(), receiver_scan_pubkey.size());
    assert(ret);

    ret = secp256k1_silentpayments_send_create_shared_secret(secp256k1_context_static,
        result_ss.data(), privkeys_tweak.data(), &scan_pubkey_obj);
    assert(ret);

    return result_ss;
}

InputPubkeysTweak CreateInputPubkeysTweak(
    const std::vector<CPubKey>& plain_pubkeys,
    const std::vector<XOnlyPubKey>& taproot_pubkeys,
    const uint256& outpoints_hash)
{
    InputPubkeysTweak result_tweak;
    std::vector<secp256k1_pubkey> plain_pubkey_objs(plain_pubkeys.size());
    std::vector<secp256k1_xonly_pubkey> taproot_pubkey_objs(taproot_pubkeys.size());

    for (size_t i = 0; i < plain_pubkeys.size(); i++) {
        bool ret = secp256k1_ec_pubkey_parse(secp256k1_context_static, &plain_pubkey_objs[i],
            plain_pubkeys[i].data(), plain_pubkeys[i].size());
        assert(ret);
    }
    for (size_t i = 0; i < taproot_pubkeys.size(); i++) {
        bool ret = secp256k1_xonly_pubkey_parse(secp256k1_context_static, &taproot_pubkey_objs[i], taproot_pubkeys[i].data());
        assert(ret);
    }

    bool ret = secp256k1_silentpayments_create_public_tweak_data(secp256k1_context_static, result_tweak.data(),
        plain_pubkey_objs.data(), plain_pubkeys.size(), taproot_pubkey_objs.data(), taproot_pubkeys.size(), outpoints_hash.data());
    assert(ret);

    return result_tweak;
}

SharedSecret CreateSharedSecretReceiver(
    const InputPubkeysTweak& pubkeys_tweak,
    const CKey& receiver_scan_privkey)
{
    SharedSecret result_ss;

    bool ret = secp256k1_silentpayments_receive_create_shared_secret(secp256k1_context_static,
        result_ss.data(), pubkeys_tweak.data(), receiver_scan_privkey.begin());
    assert(ret);

    return result_ss;
}

XOnlyPubKey CreateOutput(const SharedSecret& shared_secret, const CPubKey& receiver_spend_pubkey, uint32_t output_index)
{
    secp256k1_xonly_pubkey xpk_result_obj;
    unsigned char xpk_result_bytes[32];
    secp256k1_pubkey spend_pubkey_obj;

    bool ret = secp256k1_ec_pubkey_parse(secp256k1_context_static, &spend_pubkey_obj,
        receiver_spend_pubkey.data(), receiver_spend_pubkey.size());
    assert(ret);

    ret = secp256k1_silentpayments_create_output_pubkey(secp256k1_context_static,
        &xpk_result_obj, shared_secret.data(), &spend_pubkey_obj, output_index, NULL);
    assert(ret);

    ret = secp256k1_xonly_pubkey_serialize(secp256k1_context_static, xpk_result_bytes, &xpk_result_obj);
    assert(ret);

    return XOnlyPubKey{xpk_result_bytes};
}

}; // namespace BIP352

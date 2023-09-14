#include <wallet/silentpayments.h>
#include <addresstype.h>
#include <arith_uint256.h>
#include <bip352.h>
#include <coins.h>
#include <crypto/common.h>
#include <key_io.h>
#include <undo.h>
#include <logging.h>
#include <pubkey.h>
#include <policy/policy.h>
#include <script/sign.h>
#include <script/solver.h>
#include <util/check.h>

namespace wallet {

std::map<size_t, WitnessV1Taproot> GenerateSilentPaymentTaprootDestinations(const BIP352::InputPrivkeysTweak& tweak_data, const std::map<size_t, V0SilentPaymentDestination>& sp_dests)
{
    std::map<CPubKey, std::vector<std::pair<CPubKey, size_t>>> sp_groups;
    std::map<size_t, WitnessV1Taproot> tr_dests;

    for (const auto& [out_idx, sp_dest] : sp_dests) {
        sp_groups[sp_dest.m_scan_pubkey].emplace_back(sp_dest.m_spend_pubkey, out_idx);
    }

    for (const auto& [scan_pubkey, spend_pubkeys] : sp_groups) {
        auto shared_secret = BIP352::CreateSharedSecretSender(tweak_data, scan_pubkey);
        for (size_t i = 0; i < spend_pubkeys.size(); ++i) {
            const auto& [spend_pubkey, out_idx] = spend_pubkeys.at(i);
            tr_dests.emplace(out_idx, BIP352::CreateOutput(shared_secret, spend_pubkey, i));
        }
    }
    return tr_dests;
}

std::vector<XOnlyPubKey> GetSilentPaymentTxOutputPubkeys(const BIP352::SharedSecret& shared_secret, const CPubKey& spend_pubkey, std::vector<XOnlyPubKey> output_pub_keys)
{
    // Because a sender can create multiple outputs for us, we first check the outputs vector for an output with
    // output index 0. If we find it, we remove it from the vector and then iterate over the vector again looking for
    // an output with index 1, and so on until one of the following happens:
    //
    //     1. We have determined all outputs belong to us (the vector is empty)
    //     2. We have passed over the vector and found no outputs belonging to us
    //
    bool keep_going;
    uint32_t k{0};
    std::vector<XOnlyPubKey> found_outputs;
    do {
        // We haven't found anything yet on this pass and if we make to the end without finding any
        // silent payment outputs everything left in the vector is not for us, so we stop scanning.
        keep_going = false;

        // Compute P_k = B_spend + t_k * G, convert P_k to a P2TR output
        const XOnlyPubKey& P_k_xonly = BIP352::CreateOutput(shared_secret, spend_pubkey, k);

        // Scan the transaction outputs, only continue scanning if there is a match
        output_pub_keys.erase(std::remove_if(output_pub_keys.begin(), output_pub_keys.end(), [&](XOnlyPubKey output_pubkey) {
            bool found = P_k_xonly == output_pubkey;
            if (!found) {
                // TODO: labels support not implemented right now
            }
            if (found) {
                // Since we found an output, we need to increment k and check the vector again
                found_outputs.emplace_back(output_pubkey);
                keep_going = true;
                k++;
                // Return true so that this output pubkey is removed the from vector and not checked again
                return true;
            }
            return false;
        }), output_pub_keys.end());
    } while (!output_pub_keys.empty() && keep_going);
    return found_outputs;
}

std::optional<BIP352::InputPubkeysTweak> GetSilentPaymentsTweakDataFromTxInputs(const std::vector<CTxIn>& vin, const std::map<COutPoint, Coin>& coins)
{
    // Extract the keys from the inputs
    // or skip if no valid inputs
    std::vector<CPubKey> input_pubkeys_plain;
    std::vector<XOnlyPubKey> input_pubkeys_taproot;
    std::vector<COutPoint> input_outpoints;
    for (const CTxIn& txin : vin) {
        const Coin& coin = coins.at(txin.prevout);
        Assert(!coin.IsSpent());
        input_outpoints.emplace_back(txin.prevout);

        std::vector<std::vector<unsigned char>> solutions;
        TxoutType type = Solver(coin.out.scriptPubKey, solutions);
        if (type == TxoutType::WITNESS_V1_TAPROOT) {
            // Check for H point in script path spend
            if (txin.scriptWitness.stack.size() > 1) {
                // Check for annex
                bool has_annex = txin.scriptWitness.stack.back()[0] == ANNEX_TAG;
                size_t post_annex_size = txin.scriptWitness.stack.size() - (has_annex ? 1 : 0);
                if (post_annex_size > 1) {
                    // Actually a script path spend
                    const std::vector<unsigned char>& control = txin.scriptWitness.stack.at(post_annex_size - 1);
                    Assert(control.size() >= 33);
                    if (std::equal(NUMS_H.begin(), NUMS_H.end(), control.begin() + 1)) {
                        // Skip script path with H internal key
                        continue;
                    }
                }
            }
            input_pubkeys_taproot.emplace_back(solutions[0]);
        } else if (type == TxoutType::WITNESS_V0_KEYHASH) {
            input_pubkeys_plain.emplace_back(txin.scriptWitness.stack.back());
        } else if (type == TxoutType::PUBKEYHASH || type == TxoutType::SCRIPTHASH) {
            // Use the script interpreter to get the stack after executing the scriptSig
            std::vector<std::vector<unsigned char>> stack;
            ScriptError serror;
            Assert(EvalScript(stack, txin.scriptSig, MANDATORY_SCRIPT_VERIFY_FLAGS, DUMMY_CHECKER, SigVersion::BASE, &serror));
            if (type == TxoutType::PUBKEYHASH) {
                input_pubkeys_plain.emplace_back(stack.back());
            } else if (type == TxoutType::SCRIPTHASH) {
                // Check if the redeemScript is P2WPKH
                CScript redeem_script{stack.back().begin(), stack.back().end()};
                TxoutType rs_type = Solver(redeem_script, solutions);
                if (rs_type == TxoutType::WITNESS_V0_KEYHASH) {
                    input_pubkeys_plain.emplace_back(txin.scriptWitness.stack.back());
                }
            }
        } else if (type == TxoutType::PUBKEY) {
            input_pubkeys_plain.emplace_back(solutions[0]);
        }
    }
    if (input_pubkeys_plain.size() == 0 && input_pubkeys_taproot.size() == 0) return std::nullopt;
    const uint256& outpoints_hash = BIP352::HashOutpoints(input_outpoints);
    return BIP352::CreateInputPubkeysTweak(input_pubkeys_plain, input_pubkeys_taproot, outpoints_hash);
}
}

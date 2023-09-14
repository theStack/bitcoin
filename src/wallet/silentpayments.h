#ifndef BITCOIN_WALLET_SILENTPAYMENTS_H
#define BITCOIN_WALLET_SILENTPAYMENTS_H

#include <addresstype.h>
#include <bip352.h>
#include <coins.h>
#include <key_io.h>
#include <undo.h>

namespace wallet {

std::map<size_t, WitnessV1Taproot> GenerateSilentPaymentTaprootDestinations(
        const BIP352::InputPrivkeysTweak& tweak_data,
        const std::map<size_t,
        V0SilentPaymentDestination>& sp_dests);

std::vector<XOnlyPubKey> GetSilentPaymentTxOutputPubkeys(
        const BIP352::SharedSecret& shared_secret,
        const CPubKey& spend_pubkey,
        std::vector<XOnlyPubKey> output_pub_keys);

std::optional<BIP352::InputPubkeysTweak> GetSilentPaymentsTweakDataFromTxInputs(
        const std::vector<CTxIn>& vin,
        const std::map<COutPoint,
        Coin>& coins);
} // namespace wallet
#endif // BITCOIN_WALLET_SILENTPAYMENTS_H

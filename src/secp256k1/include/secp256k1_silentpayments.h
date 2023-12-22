#ifndef SECP256K1_SILENTPAYMENTS_H
#define SECP256K1_SILENTPAYMENTS_H

#include "secp256k1.h"
#include "secp256k1_extrakeys.h"

#ifdef __cplusplus
extern "C" {
#endif

/* This module provides an implementation for the ECC related parts of
 * Silent Payments, as specified in BIP352. This particularly involves
 * the creation of input tweak data by summing up private or public keys
 * and the derivation of a shared secret using Elliptic Curve Diffie-Hellman.
 * Combined are either:
 *   - spender's private keys and receiver's public key (a * B, sender side)
 *   - spender's public keys and receiver's private key (A * b, receiver side)
 * With this result, the necessary key material for ultimately creating/scanning
 * or spending Silent Payment outputs can be determined.
 *
 * Note that this module is _not_ a full implementation of BIP352, as it
 * inherently doesn't deal with higher-level concepts like addresses, output
 * script types or transactions. The intent is to provide cryptographical
 * helpers for low-level calculations that are most error-prone to custom
 * implementations (e.g. enforcing the right y-parity for key material, ECDH
 * calculation etc.). For any wallet software already using libsecp256k1, this
 * API should provide all the functions needed for a Silent Payments
 * implementation without the need for any further manual elliptic-curve
 * operations.
 */

/** Create Silent Payment tweak data from input private keys.
 *
 * Given a list of n private keys a_0...a_(n-1) (one for each input to spend)
 * and an outpoints_hash, compute the corresponding input private keys tweak data:
 *
 * a_tweaked = (a_0 + a_1 + ... a_(n-1)) * outpoints_hash
 *
 * If necessary, the private keys are negated to enforce the right y-parity.
 * For that reason, the private keys have to be passed in via two different parameter
 * pairs, depending on whether they were used for creating taproot outputs or not.
 * The resulting data is needed to create a shared secret for the sender side.
 *
 *  Returns: 1 if shared secret creation was successful. 0 if an error occured.
 *  Args:                  ctx: pointer to a context object
 *  Out:          tweak_data32: pointer to the resulting 32-byte tweak data
 *  In:          plain_seckeys: pointer to an array of 32-byte private keys of non-taproot inputs
 *                              (can be NULL if no private keys of non-taproot inputs are used)
 *             n_plain_seckeys: the number of sender's non-taproot input private keys
 *             taproot_seckeys: pointer to an array of 32-byte private keys of taproot inputs
 *                              (can be NULL if no private keys of taproot inputs are used)
 *           n_taproot_seckeys: the number of sender's taproot input private keys
 *            outpoints_hash32: hash of the sorted serialized outpoints
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_silentpayments_create_private_tweak_data(
    const secp256k1_context *ctx,
    unsigned char *tweak_data32,
    const unsigned char *plain_seckeys,
    size_t n_plain_seckeys,
    const unsigned char *taproot_seckeys,
    size_t n_taproot_seckeys,
    const unsigned char *outpoints_hash32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(7);

/** Create Silent Payment shared secret for the sender side.
 *
 * Given private input tweak data a_tweaked a recipient's scan public key B_scan,
 * compute the corresponding shared secret using ECDH:
 *
 * shared_secret = a_tweaked * B_scan
 * (where a_tweaked = (a_0 + a_1 + ... a_(n-1)) * outpoints_hash)
 *
 * The resulting data is needed as input for creating silent payments outputs
 * belonging to the same receiver scan public key.
 *
 *  Returns: 1 if shared secret creation was successful. 0 if an error occured.
 *  Args:                  ctx: pointer to a context object
 *  Out:       shared_secret33: pointer to the resulting 33-byte shared secret
 *  In:           tweak_data32: pointer to 32-byte private input tweak data
 *        receiver_scan_pubkey: pointer to the receiver's scan pubkey
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_silentpayments_send_create_shared_secret(
    const secp256k1_context *ctx,
    unsigned char *shared_secret33,
    const unsigned char *tweak_data32,
    const secp256k1_pubkey *receiver_scan_pubkey
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Create Silent Payment tweak data from input public keys.
 *
 * Given a list of n public keys A_0...A_(n-1) (one for each input to spend)
 * and an outpoints_hash, compute the corresponding input public keys tweak data:
 *
 * A_tweaked = (A_0 + A_1 + ... A_(n-1)) * outpoints_hash
 *
 * If necessary, the public keys are negated to enforce the right y-parity.
 * For that reason, the public keys have to be passed in via two different parameter
 * pairs, depending on whether they were used for creating taproot outputs or not.
 * The resulting data is needed to create a shared secret for the receiver's side.
 *
 *  Returns: 1 if tweak data creation was successful. 0 if an error occured.
 *  Args:                  ctx: pointer to a context object
 *  Out:          tweak_data33: pointer to the resulting 33-byte tweak data
 *  In:          plain_pubkeys: pointer to an array of non-taproot public keys
 *                              (can be NULL if no non-taproot inputs are used)
 *             n_plain_pubkeys: the number of non-taproot input public keys
 *               xonly_pubkeys: pointer to an array of taproot x-only public keys
 *                              (can be NULL if no taproot input public keys are used)
 *             n_xonly_pubkeys: the number of taproot input public keys
 *            outpoints_hash32: hash of the sorted serialized outpoints
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_silentpayments_create_public_tweak_data(
    const secp256k1_context *ctx,
    unsigned char *tweak_data33,
    const secp256k1_pubkey *plain_pubkeys,
    size_t n_plain_pubkeys,
    const secp256k1_xonly_pubkey *xonly_pubkeys,
    size_t n_xonly_pubkeys,
    const unsigned char *outpoints_hash32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(7);

/** Create Silent Payment shared secret for the receiver side.
 *
 *  Given public input tweak data A_tweaked and a recipient's scan private key
 *  b_scan, compute the corresponding shared secret using ECDH:
 *
 *  shared_secret = A_tweaked * b_scan
 *  (where A_tweaked = (A_0 + A_1 + ... A_(n-1)) * outpoints_hash)
 *
 *  The resulting data is needed as input for creating silent payments outputs
 *  belonging to the same receiver scan public key.
 *
 *  Returns: 1 if shared secret creation was successful. 0 if an error occured.
 *  Args:                  ctx: pointer to a context object
 *  Out:       shared_secret33: pointer to the resulting 33-byte shared secret
 *  In:           tweak_data33: pointer to 33-byte public input tweak data
 *        receiver_scan_seckey: pointer to the receiver's scan private key
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_silentpayments_receive_create_shared_secret(
    const secp256k1_context *ctx,
    unsigned char *shared_secret33,
    const unsigned char *tweak_data33,
    const unsigned char *receiver_scan_seckey
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Create Silent Payment output public key (both for sender and receiver).
 *
 *  Given a shared_secret, a recipient's spend public key B_spend, and an
 *  output counter k, calculate the corresponding output public key:
 *
 *  P_output = B_spend + sha256(shared_secret || ser_32(k)) * G
 *
 *  Returns: 1 if outputs creation was successful. 0 if an error occured.
 *  Args:                  ctx: pointer to a context object
 *  Out:   output_xonly_pubkey: pointer to the resulting output x-only pubkey
 *  In:        shared_secret33: shared secret, derived from either sender's
 *                              or receiver's perspective with routines from above
 *       receiver_spend_pubkey: pointer to the receiver's spend pubkey
 *                           k: output counter (usually set to 0, should be increased for
 *                              every additional output to the same recipient)
 *               label_tweak32: an optional 32-byte label tweak
 *                              (not supported yet, must be set to NULL right now)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_silentpayments_create_output_pubkey(
    const secp256k1_context *ctx,
    secp256k1_xonly_pubkey *output_xonly_pubkey,
    const unsigned char *shared_secret33,
    const secp256k1_pubkey *receiver_spend_pubkey,
    unsigned int k,
    const unsigned char *label_tweak32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Create Silent Payment output private key (for spending receiver's funds).
 *
 *  Given a shared_secret, a recipient's spend private key b_spend, and an
 *  output counter k, calculate the corresponding output private key d:
 *
 *  d = (b_spend + sha256(shared_secret || ser_32(k))) mod n
 *
 *  Returns: 1 if private key creation was successful. 0 if an error occured.
 *  Args:                  ctx: pointer to a context object
 *  Out:         output_seckey: pointer to the resulting spending private key
 *  In:        shared_secret33: shared secret, derived from either sender's
 *                              or receiver's perspective with routines from above
 *       receiver_spend_seckey: pointer to the receiver's spend private key
 *                           k: output counter (usually set to 0, should be increased for
 *                              every additional output to the same recipient)
 *               label_tweak32: an optional 32-byte label tweak
 *                              (not supported yet, must be set to NULL right now)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_silentpayments_create_output_seckey(
    const secp256k1_context *ctx,
    unsigned char *output_seckey,
    const unsigned char *shared_secret33,
    const unsigned char *receiver_spend_seckey,
    unsigned int k,
    const unsigned char *label_tweak32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_SILENTPAYMENTS_H */

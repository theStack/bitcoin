#!/usr/bin/env python3
# Copyright (c) 2024 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import argparse
import json
import logging
import os
import subprocess
import sys

PATH_BASE_CONTRIB_SILENTPAYMENTS = os.path.abspath(os.path.dirname(os.path.realpath(__file__)))
PATH_BASE_TEST_FUNCTIONAL = os.path.abspath(os.path.join(PATH_BASE_CONTRIB_SILENTPAYMENTS, "..", "..", "test", "functional"))
sys.path.insert(0, PATH_BASE_TEST_FUNCTIONAL)

from test_framework.crypto.secp256k1 import G
from test_framework.key import ORDER, generate_privkey
from test_framework.script_util import key_to_p2wpkh_script, output_key_to_p2tr_script
from test_framework.wallet_util import bytes_to_wif

logging.basicConfig(
    format='%(asctime)s %(levelname)s %(message)s',
    level=logging.INFO,
    datefmt='%Y-%m-%d %H:%M:%S')


def bitcoin_cli(basecmd, args, **kwargs):
    cmd = basecmd + ["-signet"] + args
    logging.debug("Calling bitcoin-cli: %r", cmd)
    out = subprocess.run(cmd, stdout=subprocess.PIPE, **kwargs, check=True).stdout
    if isinstance(out, bytes):
        out = out.decode('utf8')
    return out.strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--wallet", default="default_wallet", type=str, help="wallet used for funding transaction")
    parser.add_argument("--cli", default="bitcoin-cli", type=str, help="bitcoin-cli command")
    parser.add_argument("--debug", action="store_true", help="Print debugging info")

    args = parser.parse_args(sys.argv[1:])
    args.bcli = lambda *a, input=b"", **kwargs: bitcoin_cli(args.cli.split(" "), list(a), input=input, **kwargs)

    # check that provided wallet is available, show available ones if not
    available_wallets = json.loads(args.bcli("listwallets"))
    if args.wallet not in available_wallets:
        print(f"Error: wallet {args.wallet} is not available. Use one of those: {available_wallets}")

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    privkey1 = int.from_bytes(generate_privkey(), 'big')
    privkey2 = ORDER - privkey1
    pubkey1 = privkey1 * G
    pubkey2 = privkey2 * G
    # verify that points cancel each other out on addition
    # (i.e. x coordinates are equal, y coordinates differ)
    assert pubkey1.x == pubkey2.x
    assert pubkey1.y != pubkey2.y
    assert (pubkey1 + pubkey2).infinity
    # create p2wpkh addresses
    pubkey1_bytes = pubkey1.to_bytes_compressed()
    pubkey2_bytes = pubkey2.to_bytes_compressed()
    spk1 = key_to_p2wpkh_script(pubkey1_bytes)
    spk2 = key_to_p2wpkh_script(pubkey2_bytes)
    addr1 = json.loads(args.bcli("decodescript", spk1.hex()))["address"]
    addr2 = json.loads(args.bcli("decodescript", spk2.hex()))["address"]

    print(f"      Pubkey 1: {pubkey1_bytes.hex()}")
    print(f"      Pubkey 2: {pubkey2_bytes.hex()}")
    print(f"scriptPubKey 1: {spk1.hex()}")
    print(f"scriptPubKey 2: {spk2.hex()}")
    print(f"     Address 1: {addr1}")
    print(f"     Address 2: {addr2}")

    # fund the outputs
    recipients_arg = '{' + f'"{addr1}": 0.00010000, "{addr2}": 0.00010000' + '}'
    send_result = json.loads(args.bcli(f"-rpcwallet={args.wallet}", "send", recipients_arg,
        "null", "unset", "null", '{' + '"change_position": 2' + '}'))
    if not send_result["complete"]:
        print("Creating funding tx failed :/")
        sys.exit(1)
    funding_txid = send_result["txid"]
    print(f"-> Funding tx submitted: {funding_txid}\n")

    # create taproot output for spending tx
    taproot_spk = output_key_to_p2tr_script(bytes([0])*32)
    taproot_addr = json.loads(args.bcli("decodescript", taproot_spk.hex()))["address"]
    print(f"Taproot output address for spending tx: {taproot_addr}")

    # create unsigned spending tx, with the funding tx's outputs as inputs
    createtx_inputs_arg = '[' + \
        '{' + f'"txid": "{funding_txid}", "vout": 0' + '},' + \
        '{' + f'"txid": "{funding_txid}", "vout": 1' + '}'  + \
    ']'
    createtx_outputs_arg = '[{' + f'"{taproot_addr}": 0.00010000' + '}]'
    spending_tx_unsigned = args.bcli("createrawtransaction",
        createtx_inputs_arg, createtx_outputs_arg)
    logging.debug(spending_tx_unsigned)

    # convert private keys to WIF format and sign
    privkey1_wif = bytes_to_wif(privkey1.to_bytes(32, 'big'))
    privkey2_wif = bytes_to_wif(privkey2.to_bytes(32, 'big'))
    spending_tx_signed_result = json.loads(args.bcli("signrawtransactionwithkey",
        spending_tx_unsigned, f'["{privkey1_wif}", "{privkey2_wif}"]'))
    logging.debug(spending_tx_signed_result)
    if not spending_tx_signed_result["complete"]:
        print("Creating spending tx failed :/")
        sys.exit(1)

    spending_txid = args.bcli("sendrawtransaction", spending_tx_signed_result["hex"])
    print(f"-> Spending tx submitted: {spending_txid}\n")

if __name__ == "__main__":
    main()

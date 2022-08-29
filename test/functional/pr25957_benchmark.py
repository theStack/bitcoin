#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Create a giant chain for wallet performance improvement tests."""
from decimal import Decimal
import os
import time

from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import random_bytes
from test_framework.wallet_util import get_generate_key
from test_framework.wallet import getnewdestination


WALLET_BACKUP_FILENAME = '/tmp/backup.dat'
CHAIN_LENGTH = 7 * 144  # ~ one week
WALLET_TX_BLOCK_FREQUENCY = 144  # create wallet-related txs every Nth block


class GiantWallet(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [['-dbcache=50', '-acceptnonstdtxn=1', '-limitancestorsize=1000', '-limitdescendantsize=1000',
                            '-keypool=1000', '-blockfilterindex=1']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def mine_non_wallet_utxo(self, node, key):
        block_hash = self.generatetoaddress(node, 1, key.p2wpkh_addr)[0]
        coinbase_txid = node.getblock(block_hash)['tx'][0]
        utxo = [coinbase_txid, 0, Decimal("50.0")]
        self.generatetoaddress(node, 99, getnewdestination()[2])  # let the utxo mature
        return utxo

    def spend_non_wallet_utxo(self, node, key, utxo, extra_outputs):
        random_address = getnewdestination()[2]
        utxo[2] -= Decimal("0.00100000")
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(int(utxo[0], 16), utxo[1])))
        tx.vout.append(CTxOut(int(utxo[2]*100000000), bytes.fromhex(key.p2wpkh_script)))
        for _ in range(800):
            tx.vout.append(CTxOut(0, bytes.fromhex("0020") + random_bytes(20)))
        tx = tx.serialize().hex()
        tx = node.signrawtransactionwithkey(tx, [key.privkey])['hex']
        txid = node.sendrawtransaction(tx, 0)
        utxo[0] = txid

    def run_test(self):
        node = self.nodes[0]
        print("Create descriptor wallet... ")
        node.createwallet(wallet_name='foobar', descriptors=True)
        w = node.get_wallet_rpc('foobar')
        print("Create wallet backup for rescan tests later...")
        os.remove(WALLET_BACKUP_FILENAME)
        w.backupwallet(WALLET_BACKUP_FILENAME)
        print("Mine first 100 blocks...")
        self.generatetoaddress(node, 1, w.getnewaddress())
        # send/spend all non-wallet related txs to/from the same address
        key = get_generate_key()
        utxo = self.mine_non_wallet_utxo(node, key)

        total_start_time = time.time()
        for nr in range(CHAIN_LENGTH):
            start_time = time.time()        
            for _ in range(25):
                self.spend_non_wallet_utxo(node, key, utxo, [])
            if nr % WALLET_TX_BLOCK_FREQUENCY == 0:  # every nth block, include wallet-relevant tx
                w.sendtoaddress(address=w.getnewaddress(), amount=Decimal("0.01"))
            m_start_time = time.time()
            block_hash = self.generatetoaddress(node, 1, getnewdestination()[2])[0]
            mining_delay = time.time() - m_start_time
            block_res = node.getblock(block_hash)
            print("block {} mined (took {:.2f}s, mining part: {:.2f}), weight: {}".format(
                  nr+1, time.time() - start_time, mining_delay, block_res['weight']))
        print("=== {} blocks mined, took {:.2f}s ===".format(CHAIN_LENGTH, time.time() - total_start_time))

        self.nodes[0].unloadwallet('')
        print("Importing wallet backup with block filter index... ")
        start_time = time.time()
        self.nodes[0].restorewallet("wallet_rescan_slow", WALLET_BACKUP_FILENAME)
        print("    done. (took {:.3f}s)".format(time.time() - start_time))

        self.restart_node(0, ['-keypool=1000', '-blockfilterindex=0'])
        self.nodes[0].unloadwallet('')
        print("Importing wallet backup w/o block filter index...")
        start_time = time.time()
        self.nodes[0].restorewallet("wallet_rescan_fast", WALLET_BACKUP_FILENAME)
        print("    done. (took {:.3f}s)".format(time.time() - start_time))


if __name__ == '__main__':
    GiantWallet().main()

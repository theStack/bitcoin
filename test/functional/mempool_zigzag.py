#!/usr/bin/env python3
# Copyright (c) 2023 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Mempool zig zag cluster playground."""
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


class MempoolZigZagClusterTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)
        self.generate(wallet, 100)  # we need some more mature coinbase UTXOs

        parent_txids = []
        parent_utxos = []
        for _ in range(50):  # create parent txs
            res = wallet.create_self_transfer_multi(num_outputs=2)
            parent_utxos.append(res['new_utxos'])
            parent_txids.append(res['txid'])
            wallet.sendrawtransaction(from_node=node, tx_hex=res['hex'])

        child_txids = []
        for c in range(49):  # create child txs
            utxos_to_spend = [parent_utxos[c][1], parent_utxos[c+1][0]]
            res = wallet.send_self_transfer_multi(from_node=node, utxos_to_spend=utxos_to_spend)
            child_txids.append(res['txid'])

        mempool = node.getrawmempool(verbose=True)
        assert_equal(len(mempool), 99)
        for entry_txid, entry_details in mempool.items():
            if entry_txid in parent_txids:
                assert_equal(entry_details['ancestorcount'], 1)
                if entry_txid in (parent_txids[0], parent_txids[-1]):
                    assert_equal(entry_details['descendantcount'], 2)
                else:
                    assert_equal(entry_details['descendantcount'], 3)
            elif entry_txid in child_txids:
                assert_equal(entry_details['ancestorcount'], 3)
                assert_equal(entry_details['descendantcount'], 1)
            else:
                assert False


if __name__ == '__main__':
    MempoolZigZagClusterTest().main()

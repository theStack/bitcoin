#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test that package works successfully in a "network" of nodes. Send various packages from different
nodes on a network in which some nodes have already received some of the transactions (and submitted
them to mempool, kept them as orphans or rejected them as too-low-feerate transactions). The
packages should be received and accepted by all transactions on the network.
"""

from decimal import Decimal
from test_framework.messages import (
    CInv,
    MSG_WTX,
    msg_inv,
    msg_tx,
)
from test_framework.p2p import (
    P2PInterface,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    create_lots_of_big_transactions,
    gen_return_txouts,
)
from test_framework.wallet import (
    MiniWallet,
    MiniWalletMode,
)

# 1sat/vB feerate denominated in BTC/KvB
FEERATE_1SAT_VB = Decimal("0.00001000")

class PackageRelayTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 4
        self.extra_args = [[
            "-datacarriersize=100000",
            "-maxmempool=5",
            "-whitelist=noban@127.0.0.1",  # immediate tx relay
        ]] * self.num_nodes
        self.supports_cli = False

    def raise_network_minfee(self):
        filler_wallet = MiniWallet(self.nodes[0])
        relayfee = self.nodes[0].getnetworkinfo()['relayfee']
        num_big_transactions = 75
        # Generate coins to spend and wait for them to mature
        self.generate(filler_wallet, num_big_transactions)
        self.generate(filler_wallet, 100)

        self.log.debug("Create a mempool tx that will be evicted")
        tx_to_be_evicted_id = filler_wallet.send_self_transfer(from_node=self.nodes[1], fee_rate=relayfee)["txid"]

        # Increase the tx fee rate to give the subsequent transactions a higher priority in the mempool
        # The tx has an approx. vsize of 65k, i.e. multiplying the previous fee rate (in sats/kvB)
        # by 130 should result in a fee that corresponds to 2x of that fee rate
        base_fee = relayfee * 130

        self.log.debug("Fill up the mempool with txs with higher fee rate")
        txouts = gen_return_txouts()
        with self.nodes[0].assert_debug_log(["rolling minimum fee bumped"]):
            for batch_of_txid in range(num_big_transactions):
                fee = (batch_of_txid + 1) * base_fee
                create_lots_of_big_transactions(filler_wallet, self.nodes[0], fee, 1, txouts)

        self.log.debug("Wait for the network to sync mempools")
        self.sync_mempools()
        assert tx_to_be_evicted_id not in self.nodes[0].getrawmempool()

        self.log.debug("Check that all nodes' mempool minimum feerate is above min relay feerate")
        for node in self.nodes:
            assert_equal(node.getmempoolinfo()['minrelaytxfee'], FEERATE_1SAT_VB)
            assert_greater_than(node.getmempoolinfo()['mempoolminfee'], FEERATE_1SAT_VB)

    def create_packages(self):
        # Basic 1-parent-1-child package, parent 1sat/vB, child 999sat/vB
        low_fee_parent = self.wallet.create_self_transfer(fee_rate=FEERATE_1SAT_VB, confirmed_only=True)
        high_fee_child = self.wallet.create_self_transfer(utxo_to_spend=low_fee_parent["new_utxo"], fee_rate=999*FEERATE_1SAT_VB)
        package_hex_basic = [low_fee_parent["hex"], high_fee_child["hex"]]

        # Basic 1-parent-1-child package, parent 1sat/vB, child 999sat/vB
        # Parent's txid is the same as its wtxid.
        low_fee_parent_nonsegwit = self.wallet_nonsegwit.create_self_transfer(fee_rate=FEERATE_1SAT_VB, confirmed_only=True)
        assert_equal(low_fee_parent_nonsegwit["txid"], low_fee_parent_nonsegwit["wtxid"])
        high_fee_child_nonsegwit = self.wallet_nonsegwit.create_self_transfer(utxo_to_spend=low_fee_parent_nonsegwit["new_utxo"], fee_rate=999*FEERATE_1SAT_VB)
        assert_equal(high_fee_child_nonsegwit["txid"], high_fee_child_nonsegwit["wtxid"])
        package_hex_basic_nonsegwit = [low_fee_parent_nonsegwit["hex"], high_fee_child_nonsegwit["hex"]]

        # node0: sender
        # node1: pre-received the child (orphan)
        # node2: pre-received nothing
        # node3: pre-received the parent (too low fee)
        self.packages_to_submit.append(package_hex_basic)
        self.packages_to_submit.append(package_hex_basic_nonsegwit)
        self.transactions_to_presend[1] = [high_fee_child["tx"], high_fee_child_nonsegwit["tx"]]
        self.transactions_to_presend[3] = [low_fee_parent["tx"], low_fee_parent_nonsegwit["tx"]]

    def test_individual_logic(self):
        node = self.nodes[0]
        low_fee_parent = self.wallet.create_self_transfer(fee_rate=FEERATE_1SAT_VB, confirmed_only=True)
        low_fee_child = self.wallet.create_self_transfer(utxo_to_spend=low_fee_parent["new_utxo"], fee_rate=2*FEERATE_1SAT_VB)
        high_fee_child = self.wallet.create_self_transfer(utxo_to_spend=low_fee_parent["new_utxo"], fee_rate=999*FEERATE_1SAT_VB)

        peer1 = node.add_outbound_p2p_connection(P2PInterface(), p2p_idx=3, connection_type="outbound-full-relay")
        peer2 = node.add_outbound_p2p_connection(P2PInterface(), p2p_idx=4, connection_type="outbound-full-relay")

        self.log.info("Check that tx caches low feerate rejections")
        parent_wtxid_int = int(low_fee_parent["tx"].getwtxid(), 16)
        peer1.send_and_ping(msg_inv([CInv(t=MSG_WTX, h=parent_wtxid_int)]))
        peer1.wait_for_getdata([parent_wtxid_int])
        peer1.send_and_ping(msg_tx(low_fee_parent["tx"]))
        assert low_fee_parent["txid"] not in node.getrawmempool()

        # Send again from peer2, check that it is ignored
        with node.assert_debug_log([f"got inv: wtx {low_fee_parent['wtxid']}  have"]):
            peer2.send_and_ping(msg_inv([CInv(t=MSG_WTX, h=parent_wtxid_int)]))
        assert "getdata" not in peer2.last_message

        self.log.info("Check that the node doesn't try to validate a failed package again")
        # Send the (orphan) child that has a higher feerate but not enough to bump the parent
        low_child_wtxid_int = int(low_fee_child["tx"].getwtxid(), 16)
        peer1.send_and_ping(msg_inv([CInv(t=MSG_WTX, h=low_child_wtxid_int)]))
        peer1.wait_for_getdata([low_child_wtxid_int])
        peer1.send_and_ping(msg_tx(low_fee_child["tx"]))
        # Node should request the orphan's missing parent. It has seen this parent before, but only
        # cached the failure by wtxid, not txid.
        parent_txid_int = int(low_fee_parent["txid"], 16)
        peer1.wait_for_getdata([parent_txid_int])
        failed_expected_logs_1p1c = []
        failed_expected_logs_1p1c.append(f"found tx {low_fee_parent['txid']} (wtxid={low_fee_parent['wtxid']}) in reconsiderable rejects, looking for child in orphanage")
        failed_expected_logs_1p1c.append(f"found child {low_fee_child['txid']} (wtxid={low_fee_child['wtxid']}) of tx {low_fee_parent['txid']} (wtxid={low_fee_parent['wtxid']}) in orphanage, trying package evaluation")
        failed_expected_logs_1p1c.append(f"removed orphan tx {low_fee_child['txid']} (wtxid={low_fee_child['wtxid']})")

        with node.assert_debug_log(failed_expected_logs_1p1c):
            peer1.send_and_ping(msg_tx(low_fee_parent["tx"]))
        # The transactions do not get accepted due to low feerate
        assert low_fee_parent["txid"] not in node.getrawmempool()
        assert low_fee_child["txid"] not in node.getrawmempool()

        # If peer2 announces the low feerate child, it should be ignored
        with node.assert_debug_log([f"got inv: wtx {low_fee_child['wtxid']}  have"]):
            peer2.send_and_ping(msg_inv([CInv(t=MSG_WTX, h=low_child_wtxid_int)]))
        assert "getdata" not in peer2.last_message
        # If either peer sends the parent again, package evaluation should not be attempted
        with node.assert_debug_log([f"didn't evaluate package for {low_fee_parent['txid']} (wtxid={low_fee_parent['wtxid']}), no eligible child found"]):
            peer1.send_and_ping(msg_tx(low_fee_parent["tx"]))
        with node.assert_debug_log([f"didn't evaluate package for {low_fee_parent['txid']} (wtxid={low_fee_parent['wtxid']}), no eligible child found"]):
            peer2.send_and_ping(msg_tx(low_fee_parent["tx"]))

        self.log.info("Check that the node groups a low-feerate tx with its single child in orphanage")
        # Send the high feerate (orphan) child
        high_child_wtxid_int = int(high_fee_child["tx"].getwtxid(), 16)
        peer1.send_and_ping(msg_inv([CInv(t=MSG_WTX, h=high_child_wtxid_int)]))
        peer1.wait_for_getdata([high_child_wtxid_int])
        peer1.send_and_ping(msg_tx(high_fee_child["tx"]))
        # Node should request the orphan's parent, even though it has already been rejected, both by
        # itself and with a child. This is necessary, otherwise high_fee_child can be censored.
        parent_txid_int = int(low_fee_parent["txid"], 16)
        peer1.wait_for_getdata([parent_txid_int])
        expected_logs_1p1c = []
        expected_logs_1p1c.append(f"found tx {low_fee_parent['txid']} (wtxid={low_fee_parent['wtxid']}) in reconsiderable rejects, looking for child in orphanage")
        expected_logs_1p1c.append(f"found child {high_fee_child['txid']} (wtxid={high_fee_child['wtxid']}) of tx {low_fee_parent['txid']} (wtxid={low_fee_parent['wtxid']}) in orphanage, trying package evaluation")
        with node.assert_debug_log(expected_logs_1p1c):
            peer1.send_and_ping(msg_tx(low_fee_parent["tx"]))

        # Both transactions should now be in mempool
        node_mempool = node.getrawmempool()
        assert low_fee_parent["txid"] in node_mempool
        assert high_fee_child["txid"] in node_mempool

        peer1.peer_disconnect()
        peer2.peer_disconnect()
        self.sync_all()

    def test_e2e_package_relay(self):
        self.log.info("Create transactions and then mature the coinbases")
        self.packages_to_submit = []
        self.transactions_to_presend = [[]] * self.num_nodes

        self.wallet.rescan_utxos(include_mempool=True)
        self.create_packages()

        self.peers = []
        for i in range(self.num_nodes):
            self.peers.append(self.nodes[i].add_outbound_p2p_connection(P2PInterface(), p2p_idx=i, connection_type="outbound-full-relay"))

        self.log.info("Pre-send some transactions to nodes")
        for i in range(self.num_nodes):
            peer = self.peers[i]
            for tx in self.transactions_to_presend[i]:
                inv = CInv(t=MSG_WTX, h=int(tx.getwtxid(), 16))
                peer.send_and_ping(msg_inv([inv]))
                peer.wait_for_getdata([int(tx.getwtxid(), 16)])
                peer.send_and_ping(msg_tx(tx))
            # This disconnect removes any sent orphans from the orphanage (EraseForPeer) and times
            # out the in-flight requests.  It is currently required for the test to pass right now,
            # because the node will not (re)try requesting orphan parents from multiple peers if the
            # first one fails.
            # TODO: remove this and test that the node retries orphan resolution with other peers
            # when the first try fails.
            peer.peer_disconnect()

        self.log.info("Submit full packages to node0")
        for package_hex in self.packages_to_submit:
            self.nodes[0].submitpackage(package_hex)

        self.log.info("Wait for mempools to sync")
        self.sync_mempools(timeout=20)

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[1])
        self.wallet_nonsegwit = MiniWallet(self.nodes[2], mode=MiniWalletMode.RAW_P2PK)
        self.generate(self.wallet_nonsegwit, 10)
        self.generate(self.wallet, 120)

        self.log.info("Fill mempools with large transactions to raise mempool minimum feerates")
        self.raise_network_minfee()

        self.log.info("Check 1p1c validation logic on a single node")
        self.test_individual_logic()

        self.log.info("Check end-to-end package relay across multiple nodes")
        self.test_e2e_package_relay()


if __name__ == '__main__':
    PackageRelayTest().main()

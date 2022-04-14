#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the getreceivedyb{address,label} RPCs for PR #23662."""
from time import sleep, time
from test_framework.test_framework import BitcoinTestFramework
from test_framework.wallet import getnewdestination


class PR23662_ReceivedByTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        LABEL_NAME = "myfancylabel"
        print("Generating 500 txs with 10 outputs each (have IsMine not set)..")
        for i in range(500):
            # node0 -> node1 (IsMine unset on node0)
            addrs = [getnewdestination()[2] for _ in range(10)]
            [self.nodes[0].setlabel(addr, LABEL_NAME) for addr in addrs]
            txid = self.nodes[0].sendmany("",
                    {addrs[0]:  0.0001,
                     addrs[1]:  0.0001,
                     addrs[2]:  0.0001,
                     addrs[3]:  0.0001,
                     addrs[4]:  0.0001,
                     addrs[5]:  0.0001,
                     addrs[6]:  0.0001,
                     addrs[7]:  0.0001,
                     addrs[8]:  0.0001,
                     addrs[9]:  0.0001,})
            # mine into block every now and then
            if (i+1) % 100 == 0:
                self.generate(self.nodes[0], 1)
                print(f"{(i+1)}/500 txs created")

        print("Generating 500 txs with 10 outputs each (have IsMine not set, no label)..")
        for i in range(500):
            # node0 -> node1 (IsMine unset on node0)
            addrs = [getnewdestination()[2] for _ in range(10)]
            #[self.nodes[0].setlabel(addr, LABEL_NAME) for addr in addrs]
            txid = self.nodes[0].sendmany("",
                    {addrs[0]:  0.0001,
                     addrs[1]:  0.0001,
                     addrs[2]:  0.0001,
                     addrs[3]:  0.0001,
                     addrs[4]:  0.0001,
                     addrs[5]:  0.0001,
                     addrs[6]:  0.0001,
                     addrs[7]:  0.0001,
                     addrs[8]:  0.0001,
                     addrs[9]:  0.0001,})
            # mine into block every now and then
            if (i+1) % 100 == 0:
                self.generate(self.nodes[0], 1)
                print(f"{(i+1)}/500 txs created")

        print("Generating 500 txs with 10 outputs each (have IsMine set)..")
        for i in range(500):
            # node1 -> node0 (IsMine set on node0)
            addrs = [self.nodes[0].getnewaddress(LABEL_NAME) for _ in range(10)]
            txid = self.nodes[1].sendmany("",
                    {addrs[0]:  0.0001,
                     addrs[1]:  0.0001,
                     addrs[2]:  0.0001,
                     addrs[3]:  0.0001,
                     addrs[4]:  0.0001,
                     addrs[5]:  0.0001,
                     addrs[6]:  0.0001,
                     addrs[7]:  0.0001,
                     addrs[8]:  0.0001,
                     addrs[9]:  0.0001,})
            # mine into block every now and then
            if (i+1) % 100 == 0:
                self.generate(self.nodes[1], 1)
                print(f"{(i+1)}/500 txs created")

        assert len(self.nodes[0].getaddressesbylabel(LABEL_NAME)) == 10000

        print("Calling getreceivedbyaddress RPC...")
        t1 = time()
        res = self.nodes[0].getreceivedbyaddress(addrs[0])
        dur_ms = (time() - t1) * 1000
        print(f"=> took {dur_ms}ms (RPC result: {res})")

        print("Calling getreceivedbylabel RPC (label on single tx)...")
        self.nodes[0].setlabel(addrs[1], "otherlabel")
        t1 = time()
        res = self.nodes[0].getreceivedbylabel("otherlabel")
        dur_ms = (time() - t1) * 1000
        print(f"=> took {dur_ms}ms (RPC result: {res})")

        print("Calling getreceivedbylabel RPC (label on ALL txs)...")
        t1 = time()
        res = self.nodes[0].getreceivedbylabel(LABEL_NAME)
        dur_ms = (time() - t1) * 1000
        print(f"=> took {dur_ms}ms (RPC result: {res})")


if __name__ == '__main__':
    PR23662_ReceivedByTest().main()

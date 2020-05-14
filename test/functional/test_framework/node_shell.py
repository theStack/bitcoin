#!/usr/bin/env python3
# Copyright (c) 2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Node shell - interact with a local running bitcoind node with RPC and P2P

Before running, there should be a config.ini file in /bitcoin/test/config.ini.

Example usage:

→ python
Python 3.7.5 (default, Nov 20 2019, 09:21:52)
[GCC 9.2.1 20191008] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import sys
>>> sys.path.insert(0, "<path to repo>/bitcoin/test/functional")
>>> from test_framework.node_shell import NodeShell
>>> test = NodeShell()
>>> test.setup(datadir="<path to datadir>/.bitcoin")
<test_framework.node_shell.NodeShell.__TestShell object at 0x7f7704820490>
>>> test.nodes[0].getnetworkinfo()
{'version': 199900, 'subversion': '/Satoshi:0.19.99/', ...
>>> test.shutdown()
2020-04-21T15:51:54.904000Z TestFramework (INFO): Note: bitcoinds were not stopped and may still be running
2020-04-21T15:51:54.905000Z TestFramework (WARNING): Not cleaning up dir /tmp/bitcoin_func_test_mt7q4p6c
2020-04-21T15:51:54.905000Z TestFramework (INFO): Tests successful
"""

from test_framework.mininode import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import (
    get_rpc_proxy,
    rpc_url,
)

class NodeShell:
    """Wrapper Class for BitcoinTestFramework.

    The NodeShell class extends the BitcoinTestFramework
    rpc & daemon process management functionality to external
    python environments.

    It is a singleton class, which ensures that users only
    start a single NodeShell at a time."""

    class __TestShell(BitcoinTestFramework):
        def set_test_params(self):
            pass

        def run_test(self):
            pass

        def setup(self, **kwargs):
            if self.running:
                print("NodeShell is already running!")
                return

            self.num_nodes = 1
            self.chain = 'mainnet'
            self.options.noshutdown = True

            if 'datadir' not in kwargs:
                print("Must provide datadir parameter")
                return
            self.datadir = kwargs.pop('datadir')

            # User parameters override default values.
            for key, value in kwargs.items():
                if hasattr(self, key):
                    setattr(self, key, value)
                elif hasattr(self.options, key):
                    setattr(self.options, key, value)
                else:
                    raise KeyError(key + " not a valid parameter key!")

            super().setup()
            self.running = True
            return self

        def setup_chain(self):
            pass

        def setup_network(self):
            self.nodes = [TestNode(i=0,
                                   datadir=self.datadir,
                                   chain='mainnet',
                                   rpchost="localhost:8332",
                                   timewait=self.rpc_timeout,
                                   factor=1.0,
                                   bitcoind=[self.options.bitcoind],
                                   bitcoin_cli=[self.options.bitcoincli],
                                   coverage_dir=self.options.coveragedir,
                                   cwd=self.options.tmpdir)]

            # Connect RPC
            node = self.nodes[0]
            node.rpc = get_rpc_proxy(rpc_url(node.datadir, node.index, node.chain, node.rpchost), node.index, timeout=node.rpc_timeout, coveragedir=node.coverage_dir)
            node.rpc_connected = True
            node.url = node.rpc.url

            # Add P2P connection
            node.add_p2p_connection(P2PInterface(), dstport=8333)

        def shutdown(self):
            if not self.running:
                print("NodeShell is not running!")
            else:
                self.nodes = []
                super().shutdown()
                self.running = False

        def reset(self):
            if self.running:
                print("Shutdown NodeShell before resetting!")
            else:
                self.num_nodes = None
                super().__init__()

    instance = None

    def __new__(cls):
        # This implementation enforces singleton pattern, and will return the
        # previously initialized instance if available
        if not NodeShell.instance:
            NodeShell.instance = NodeShell.__TestShell()
            NodeShell.instance.running = False
        return NodeShell.instance

    def __getattr__(self, name):
        return getattr(self.instance, name)

    def __setattr__(self, name, value):
        return setattr(self.instance, name, value)

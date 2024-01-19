#!/usr/bin/env python3
# Copyright (c) 2024 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test P2P behaviour during the handshake phase (VERSION, VERACK messages).
"""
import random

from test_framework.test_framework import BitcoinTestFramework
from test_framework.messages import (
    NODE_NETWORK,
    NODE_NONE,
    NODE_WITNESS,
)
from test_framework.p2p import P2PInterface


DESIRABLE_SERVICE_FLAGS = NODE_NETWORK | NODE_WITNESS


class P2PHandshakeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def check_outbound_disconnect(self, node, p2p_idx, connection_type, services):
        node.add_outbound_p2p_connection(
            P2PInterface(), p2p_idx=p2p_idx, wait_for_disconnect=True,
            connection_type=connection_type, services=services)

    def run_test(self):
        node = self.nodes[0]
        self.log.info("Check that lacking desired service flags leads to disconnect")
        for i, conn_type in enumerate(["outbound-full-relay", "block-relay-only", "addr-fetch"]):
            services = random.choice([NODE_NONE, NODE_NETWORK, NODE_WITNESS])
            assert (services & DESIRABLE_SERVICE_FLAGS) != DESIRABLE_SERVICE_FLAGS
            expected_debug_log = f'peer={i} does not offer the expected services ' \
                    f'({services:08x} offered, {DESIRABLE_SERVICE_FLAGS:08x} expected)'
            self.log.info(f'    - services 0x{services:08x}, type "{conn_type}"')
            with node.assert_debug_log([expected_debug_log]):
                self.check_outbound_disconnect(node, i, conn_type, services)

        self.log.info("Check that feeler connections get disconnected immediately")
        with node.assert_debug_log(["feeler connection completed"]):
            self.check_outbound_disconnect(node, i+1, "feeler", NODE_NONE)


if __name__ == '__main__':
    P2PHandshakeTest().main()

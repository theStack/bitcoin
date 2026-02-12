#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test signet miner tool"""

import os.path
import subprocess
import sys
import time

from test_framework.blocktools import COINBASE_MATURITY, DIFF_1_N_BITS
from test_framework.key import ECKey
from test_framework.script_util import key_to_p2wpkh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet
from test_framework.wallet_util import bytes_to_wif


CHALLENGE_PRIVATE_KEY = (42).to_bytes(32, 'big')


class SignetMinerTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.chain = "signet"
        self.setup_clean_chain = True
        self.num_nodes = 1

        # generate and specify signet challenge (simple p2wpkh script)
        privkey = ECKey()
        privkey.set(CHALLENGE_PRIVATE_KEY, True)
        pubkey = privkey.get_pubkey().get_bytes()
        challenge = key_to_p2wpkh_script(pubkey)
        self.extra_args = [[f'-signetchallenge={challenge.hex()}']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_cli()
        self.skip_if_no_wallet()
        self.skip_if_no_bitcoin_util()

    # TODO: this is a copy of `mine_block` below, the only difference
    # being that `--max-blocks` is passed instead of `--set-block-time`
    def mine_initial_blocks(self, node, num_blocks):
        n_blocks = node.getblockcount()
        base_dir = self.config["environment"]["SRCDIR"]
        signet_miner_path = os.path.join(base_dir, "contrib", "signet", "miner")
        subprocess.run([
                sys.executable,
                signet_miner_path,
                f'--cli={node.cli.binary} -datadir={node.cli.datadir}',
                'generate',
                f'--address={self.wallet_addr}',
                f'--grind-cmd={self.options.bitcoinutil} grind',
                f'--nbits={DIFF_1_N_BITS:08x}',
                f'--max-blocks={num_blocks}',
                '--poolnum=99',
            ], check=True, stderr=subprocess.STDOUT)
        assert_equal(node.getblockcount(), n_blocks + num_blocks)

    def mine_block(self, node, custom_txs_file=None):
        n_blocks = node.getblockcount()
        base_dir = self.config["environment"]["SRCDIR"]
        signet_miner_path = os.path.join(base_dir, "contrib", "signet", "miner")
        custom_txs_arg = [f'--custom-txs-file={custom_txs_file}'] if custom_txs_file else []
        subprocess.run([
                sys.executable,
                signet_miner_path,
                f'--cli={node.cli.binary} -datadir={node.cli.datadir}',
                'generate',
                f'--address={node.getnewaddress()}',
                f'--grind-cmd={self.options.bitcoinutil} grind',
                f'--nbits={DIFF_1_N_BITS:08x}',
                f'--set-block-time={int(time.time())}',
                '--poolnum=99',
            ] + custom_txs_arg, check=True, stderr=subprocess.STDOUT)
        assert_equal(node.getblockcount(), n_blocks + 1)

    def run_test(self):
        node = self.nodes[0]
        # import private key needed for signing block
        node.importprivkey(bytes_to_wif(CHALLENGE_PRIVATE_KEY))

        self.log.info("Mine blocks to create spendable UTXOs (mature coinbase outputs)")
        self.wallet = MiniWallet(node)
        # translate MiniWallet address to Signet (due to different bech32 HRP)
        self.wallet_addr = node.decodescript(self.wallet.get_output_script().hex())['address']

        self.mine_initial_blocks(node, COINBASE_MATURITY + 5)
        self.wallet.rescan_utxos()
        assert len(self.wallet.get_utxos(include_immature_coinbase=False, mark_as_spent=False)) > 0

        self.log.info("Mine block with overrided txs (provided by --custom-tx-file)")
        # submit transaction to mempool, should be picked up by the miner
        mempool_tx = self.wallet.send_self_transfer(from_node=node)
        self.mine_block(node)
        mined_block = node.getblock(node.getbestblockhash())
        assert_equal(len(mined_block['tx']), 2)  # coinbase + miniwallet tx
        assert_equal(mined_block['tx'][1], mempool_tx['txid'])

        # submit transaction to mempool, override with some custom (non-standard) txs
        mempool_tx = self.wallet.send_self_transfer(from_node=node)
        offband_txs = [self.wallet.create_self_transfer(target_vsize=333_000) for _ in range(3)]
        custom_txs_file = os.path.join(self.options.tmpdir, "fancy_offband_txs.txt")
        with open(custom_txs_file, 'w') as f:
            f.write('# this is my fancy off-band transaction, please mine!\n')
            for offband_tx in offband_txs:
                f.write(offband_tx['hex'] + '\n')
        self.mine_block(node, custom_txs_file)
        mined_block = node.getblock(node.getbestblockhash())
        assert mined_block['size'] > 990_000
        assert_equal(len(mined_block['tx']), 1 + len(offband_txs))
        assert mempool_tx['txid'] not in mined_block['tx']
        for offband_tx in offband_txs:
            assert offband_tx['txid'] in mined_block['tx']


if __name__ == "__main__":
    SignetMinerTest(__file__).main()

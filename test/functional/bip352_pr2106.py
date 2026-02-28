#!/usr/bin/env python3
from hashlib import sha256
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut
from test_framework.script_util import output_key_to_p2tr_script
from test_framework.test_framework import BitcoinTestFramework


class BIP352_PR2106(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        # create taproot funding tx
        funding_addr = self.nodes[0].getnewaddress("", "bech32m")
        funding_txid = self.nodes[0].sendtoaddress(funding_addr, 0.1)

        # create 1-in-K_max-out P2TR transactions
        for K_max in range(2322, 2325):
            tx = CTransaction()
            tx.vin.append(CTxIn(COutPoint(int(funding_txid, 16), 0)))
            for i in range(K_max):
                xonly_pubkey = sha256(i.to_bytes(4, 'little')).digest()
                output_script = output_key_to_p2tr_script(xonly_pubkey)
                tx.vout.append(CTxOut(nValue=1000, scriptPubKey=output_script))
            res = self.nodes[0].signrawtransactionwithwallet(tx.serialize().hex())
            assert res["complete"]
            vsize = self.nodes[0].decoderawtransaction(res["hex"])["vsize"]
            res = self.nodes[0].testmempoolaccept([res["hex"]], 0)[0]
            print(f"1-in-{K_max}-out P2TR tx: vsize = {vsize} (allowed={res['allowed']})")


if __name__ == '__main__':
    BIP352_PR2106(__file__).main()

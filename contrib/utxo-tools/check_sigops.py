#!/usr/bin/env python3
import os
import sqlite3
import sys

PATH_BASE_CONTRIB_UTXO_TOOLS = os.path.abspath(os.path.dirname(os.path.realpath(__file__)))
PATH_BASE_TEST_FUNCTIONAL = os.path.abspath(os.path.join(PATH_BASE_CONTRIB_UTXO_TOOLS, "..", "..", "test", "functional"))
sys.path.insert(0, PATH_BASE_TEST_FUNCTIONAL)

from test_framework.script import CScript, CScriptInvalidError


def main(args):
    if len(args) != 2:
        print(f"Usage: {args[0]} <utxos-sqlite-db>")
        sys.exit(1)
    con = sqlite3.connect(args[1])
    cur = con.cursor()

    """
    # schema: (txid TEXT, vout INT, value INT, coinbase INT, height INT, sigops INT, scriptpubkey TEXT)
    for row in cur.execute("SELECT * FROM utxos ORDER BY height"):
        txid, vout, value, coinbase, height, sigops, scriptpubkey = row
        bitcoind_sigops = sigops
        try:
            testframework_sigops = CScript(bytes.fromhex(scriptpubkey)).GetSigOpCount(True)
        except CScriptInvalidError as err:
            print(f"-> {txid[:8]}...:{vout} in block {height}: {value} sats, spk: {scriptpubkey}")
            continue
        assert bitcoind_sigops == testframework_sigops
    """
    # schema: (txid TEXT, vout INT, value INT, coinbase INT, height INT, sigops INT, scriptpubkey TEXT)
    for row in cur.execute("SELECT * FROM utxos ORDER BY sigops DESC LIMIT 10"):
        txid, vout, value, coinbase, height, sigops, scriptpubkey = row
        bitcoind_sigops = sigops
        print(f"-> [{sigops} sigops] {txid[:8]}...:{vout} in block {height}: {value} sats, spk: {scriptpubkey}")
        try:
            testframework_sigops = CScript(bytes.fromhex(scriptpubkey)).GetSigOpCount(True)
        except CScriptInvalidError as err:
            continue
        assert bitcoind_sigops == testframework_sigops

    con.close()


if __name__ == '__main__':
    main(sys.argv)

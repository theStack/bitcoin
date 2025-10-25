#!/usr/bin/env bash
zig run ./utxo_to_sqlite.zig -lsqlite3 -lc -- $1 $2

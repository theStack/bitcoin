#!/usr/bin/env bash
zig run ./utxo_to_sqlite.zig -lsqlite3 -lc -OReleaseFast -- $1 $2
#zig run ./utxo_to_sqlite.zig -lsqlite3 -lc -- $1 $2

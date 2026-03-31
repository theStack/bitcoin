#!/usr/bin/env bash
set -e

echo "----- Build log -----" > build.log
if [ -d ../build ]; then
    echo "Bitcoin Core build folder already exists, skip creating cmake build configuration."
else
    echo "Create cmake build configuration..."
    cmake -S .. -B ../build -DCMAKE_BUILD_TYPE=Release -DBUILD_KERNEL_LIB=ON -DBUILD_SHARED_LIBS=OFF -DBUILD_DAEMON=OFF -DBUILD_CLI=OFF -DENABLE_WALLET=OFF -DBUILD_TESTS=OFF >> build.log 2>&1
fi
echo "(Re)building libbitcoinkernel..."
cmake --build ../build -j6 > build.log 2>&1
echo "Building BIP-352 worst-case scanning block benchmark..."
make clean >> build.log 2>&1
make >> build.log 2>&1
./bip352_signet_scan_worstcase_block

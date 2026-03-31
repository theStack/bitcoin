bip352_signet_scan_worstcase_bench: bip352_signet_scan_worstcase_block.c
	cc -O3 -I "../src/kernel" -I "../src/secp256k1/include" bip352_signet_scan_worstcase_block.c -L "../build/lib" -lbitcoinkernel -lm -lstdc++ -o bip352_signet_scan_worstcase_block
	strip bip352_signet_scan_worstcase_block

.PHONY: clean

clean:
	rm -f bip352_signet_scan_worstcase_block

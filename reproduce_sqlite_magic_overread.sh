#!/bin/bash
python3 -c "print('A'*512)" > /tmp/corrupt_wallet
./src/test/test_bitcoin --log_level=all --run_test=db_tests


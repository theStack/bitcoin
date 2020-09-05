#!/usr/bin/env python3
import hashlib, sha3_sipa
import os, random

def sha3_256_python(input):
    return hashlib.new('sha3_256', input).digest()

def sha3_256_sipa(input):
    return sha3_sipa.SHA3_256().Write(input).Finalize()

i = 0
while True:
    random_input = os.urandom(random.randint(0,1024*1024))
    assert(sha3_256_sipa(random_input) == sha3_256_python(random_input))
    i += 1
    if i % 1000 == 0:
        print("{} random input checks passed.".format(i))

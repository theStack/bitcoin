#!/usr/bin/env python3
from test_framework.ellswift import xelligatorswift
from test_framework.key import ECKey

# evaluate how much computational power is needed to circumvent censorship on
# BIP324 connections by the GFW (great firewall of china) based on the exemption
# rules listed in paper https://gfw.report/publications/usenixsecurity23/en/
# ("How the Great Firewall of China Detects and Blocks Fully Encrypted Traffic"
#   by Mingshi Wu, Jackson Sippe, Danesh Sivakumar, Jack Burg, Peter Anderson,
#      Xiaokang Wang, Kevin Bock, Amir Houmansadr, Dave Levin, Eric Wustrow)

# the first package in the BIP324 handshake is an elligator-swift encoded
# pseudo-random looking pubkey, so arbitrarly modifying data parts as suggested
# in paper (e.g. setting a printable prefix) is not possible. what we can do
# instead is sacrificing CPU power and repeatedly do pubkey -> ellswift-pubkey
# encoding rounds until the result matches one of the exemption rules Ex1, Ex2
# and Ex3. Note that exemptions Ex4 and Ex5 are infeasible with this crunching
# approach and are therefore not evaluated.

def test_gfw_exemption(ex_func, comment):
    ex_name = ex_func.__name__
    print(f'===== Checking BIP324 bypass for GFW using {ex_name} ("{comment}") ===')
    total_i = 0
    test_runs = 0
    while True:
        print(f'Test run {test_runs+1}... ', end='', flush=True)
        privkey = ECKey()
        privkey.generate()
        pubkey_x_fe = privkey.get_pubkey().p.x

        i = 0
        while True:
            u, t = xelligatorswift(pubkey_x_fe)
            ellswift_pubkey = u.to_bytes() + t.to_bytes()
            i += 1
            if ex_func(ellswift_pubkey):
                break
        total_i += i
        test_runs += 1

        print(f'found ellswift-pubkey satisfying {ex_name} after {i} rounds')
        #print(ellswift_pubkey.hex())
        if test_runs >= 50:
            break

    print(f'Needs {total_i/test_runs} rounds on average to find an encoding satisfying {ex_name}.\n')

def Ex1(pkt):
    popcount = int.from_bytes(pkt, 'big').bit_count()
    return popcount/len(pkt) <= 3.4 or popcount/len(pkt) >= 4.6

def Ex2(pkt):
    for c in pkt[:6]:
        if not (0x20 <= c <= 0x7e):
            return False
    return True

def Ex3(pkt):
    printables = sum(1 for c in pkt if 0x20 <= c <= 0x7e)
    return printables/len(pkt) > 0.5

def Ex4(pkt):
    for start_idx in range(0, len(pkt)-20+1):
        found = True
        for c in pkt[start_idx:start_idx+20]:
            if not (0x20 <= c <= 0x7e):
                found = False
                break
        if found:
            return True
    return False

def Ex1Ex2Ex3(pkt):
    return Ex1(pkt) or Ex2(pkt) or Ex3(pkt)

test_gfw_exemption(Ex1, "Entropy Exemption")
test_gfw_exemption(Ex2, "First six bytes are printable")
test_gfw_exemption(Ex3, "Half of the first packet are printable")
# don't execute Ex4, as it's infeasible
#test_gfw_exemption(Ex4, "More than 20 contiguous bytes are printable")
test_gfw_exemption(Ex1Ex2Ex3, "any of Ex1, Ex2 or Ex3")

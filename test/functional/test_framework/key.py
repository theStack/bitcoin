# Copyright (c) 2019-2020 Pieter Wuille
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test-only secp256k1 elliptic curve implementation

WARNING: This code is slow, uses bad randomness, does not properly protect
keys, and is trivially vulnerable to side channel attacks. Do not use for
anything but tests."""
import csv
import hashlib
import hmac
import os
import random
import unittest

from .util import modinv

# Point with no known discrete log.
H_POINT = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"


def TaggedHash(tag, data):
    ss = hashlib.sha256(tag.encode('utf-8')).digest()
    ss += ss
    ss += data
    return hashlib.sha256(ss).digest()

class FE:
    """Objects of this class represent elements of the field GF(2**256 - 2**32 - 977).

    They are represented internally in numerator / denominator form, in order to delay inversions.
    """

    SIZE = 2**256 - 2**32 - 977

    def __init__(self, a=0, b=1):
        """Initialize an FE as a/b; both a and b can be ints or field elements."""
        if isinstance(b, FE):
            if isinstance(a, FE):
                self.num = (a.num * b.den) % FE.SIZE
                self.den = (a.den * b.num) % FE.SIZE
            else:
                self.num = (a * b.den) % FE.SIZE
                self.den = b.num
        else:
            b = b % FE.SIZE
            assert b != 0
            if isinstance(a, FE):
                self.num = a.num
                self.den = (a.den * b) % FE.SIZE
            else:
                self.num = a % FE.SIZE
                self.den = b

    def __add__(self, a):
        """Compute the sum of two field elements (second may be int)."""
        if isinstance(a, FE):
            return FE(self.num * a.den + self.den * a.num, self.den * a.den)
        return FE(self.num + self.den * a, self.den)

    def __radd__(self, a):
        """Compute the sum of an integer and a field element."""
        return FE(self.num + self.den * a, self.den)

    def __sub__(self, a):
        """Compute the difference of two field elements (second may be int)."""
        if isinstance(a, FE):
            return FE(self.num * a.den - self.den * a.num, self.den * a.den)
        return FE(self.num - self.den * a, self.den)

    def __rsub__(self, a):
        """Compute the difference between an integer and a field element."""
        return FE(self.den * a - self.num, self.den)

    def __mul__(self, a):
        """Compute the product of two field elements (second may be int)."""
        if isinstance(a, FE):
            return FE(self.num * a.num, self.den * a.den)
        return FE(self.num * a, self.den)

    def __rmul__(self, a):
        """Compute the product of an integer with a field element."""
        return FE(self.num * a, self.den)

    def __truediv__(self, a):
        """Compute the ratio of two field elements (second may be int)."""
        return FE(self, a)

    def __rtruediv__(self, a):
        """Compute the ratio of an integer and a field element."""
        return FE(a, self)

    def __pow__(self, a):
        """Raise a field element to a (positive) integer power."""
        return FE(pow(self.num, a, FE.SIZE), pow(self.den, a, FE.SIZE))

    def __neg__(self):
        """Negate a field element."""
        return FE(-self.num, self.den)

    def __int__(self):
        """Convert a field element to an integer. The result is cached."""
        if self.den != 1:
            self.num = (self.num * modinv(self.den, FE.SIZE)) % FE.SIZE
            self.den = 1
        return self.num

    def sqrt(self):
        """Compute the square root of a field element.

        Due to the fact that our modulus is of the form (p % 4) == 3, the Tonelli-Shanks
        algorithm (https://en.wikipedia.org/wiki/Tonelli-Shanks_algorithm) is simply
        raising the argument to the power (p + 3) / 4.

        To see why: (p-1) % 2 = 0, so 2 divides the order of the multiplicative group,
        and thus only half of the non-zero field elements are squares. An element a is
        a (nonzero) square when Euler's criterion, a^((p-1)/2) = 1 (mod p), holds. We're
        looking for x such that x^2 = a (mod p). Given a^((p-1)/2) = 1, that is equivalent
        to x^2 = a^(1 + (p-1)/2) mod p. As (1 + (p-1)/2) is even, this is equivalent to
        x = a^((1 + (p-1)/2)/2) mod p, or x = a^((p+1)/4) mod p."""
        v = int(self)
        s = pow(v, (FE.SIZE + 1) // 4, FE.SIZE)
        if s**2 % FE.SIZE == v:
            return FE(s)
        return None

    def is_square(self):
        """Determine if this field element has a square root."""
        # Compute the Jacobi symbol of (self / p). Since our modulus is prime, this
        # is the same as the Legendre symbol, which determines quadratic residuosity.
        # See https://en.wikipedia.org/wiki/Jacobi_symbol for the algorithm.
        # Note that num*den = (num/den) * den^2 has the same squareness as num/den,
        # because they are related by a factor that is definitely square.
        n, k, t = (self.num * self.den) % FE.SIZE, FE.SIZE, 0
        if n == 0:
            return True
        while n != 0:
            while n & 1 == 0:
                n >>= 1
                r = k & 7
                t ^= (r in (3, 5))
            n, k = k, n
            t ^= (n & k & 3 == 3)
            n = n % k
        assert k == 1
        return not t

    def is_even(self):
        """Determine whether this field element, represented as integer in 0..p-1, is even."""
        return int(self) & 1 == 0

    def __eq__(self, a):
        """Check whether two field elements are equal (second may be an int)."""
        if isinstance(a, FE):
            return (self.num * a.den - self.den * a.num) % FE.SIZE == 0
        return (self.num - self.den * a) % FE.SIZE == 0

    def to_bytes(self):
        """Convert a field element to 32-byte big endian encoding."""
        return int(self).to_bytes(32, 'big')

    @staticmethod
    def from_bytes(b):
        """Convert a 32-byte big endian encoding of a field element to an FE."""
        v = int.from_bytes(b, 'big')
        if v >= FE.SIZE:
            return None
        return FE(v)

    def __str__(self):
        """Convert this field element to a string."""
        return f"{int(self):064x}"

    def __repr__(self):
        """Get a string representation of this field element."""
        return f"FE(0x{int(self):x})"

class GE:
    """Objects of this class represent points (group elements) on the secp256k1 curve.

    The point at infinity is represented as None."""

    ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    ORDER_HALF = ORDER // 2

    def __init__(self, x, y):
        """Initialize a group element with specified x and y coordinates (must be on curve)."""
        fx = FE(x)
        fy = FE(y)
        assert fy**2 == fx**3 + 7
        self.x = fx
        self.y = fy

    def double(self):
        """Compute the double of a point."""
        l = 3 * self.x**2 / (2 * self.y)
        x3 = l**2 - 2 * self.x
        y3 = l * (self.x - x3) - self.y
        return GE(x3, y3)

    def __add__(self, a):
        """Add two points, or a point and infinity, together."""
        if a is None:
            # Adding point at infinity
            return self
        if self.x != a.x:
            # Adding distinct x coordinates
            l = (a.y - self.y) / (a.x - self.x)
            x3 = l**2 - self.x - a.x
            y3 = l * (self.x - x3) - self.y
            return GE(x3, y3)
        if self.y == a.y:
            # Adding point to itself
            return self.double()
        # Adding point to its negation
        return None

    def __radd__(self, a):
        """Add infinity to a point."""
        assert a is None
        return self

    def __sub__(self, a):
        """Subtract two points, or subtract infinity from a point."""
        if a is None:
            return self
        return self + (-a)

    def __rsub__(self, a):
        """Subtract a point from infinity."""
        assert a is None
        return -a

    def __mul__(self, a):
        """Multiply a point with an integer (scalar multiplication)."""
        r = None
        for i in range(a.bit_length() - 1, -1, -1):
            if r is not None:
                r = r.double()
            if (a >> i) & 1:
                r += self
        return r

    def __rmul__(self, a):
        """Multiply an integer with a point (scalar multiplication)."""
        return self * a

    @staticmethod
    def mmul(*ps):
        """Compute a (multi) point multiplication.

        mmul((p1, a1), (p2, a2), (p3, a3)) is identical to p1*a1 + p2*a2 + p3*a3,
        but more efficient."""
        r = None
        for i in range(255, -1, -1):
            if r is not None:
                r = r.double()
            for (p, n) in ps:
                if ((n >> i) & 1):
                    r += p
        return r

    def __neg__(self):
        """Compute the negation of a point."""
        return GE(self.x, -self.y)

    def to_bytes_compressed(self):
        """Convert a point to 33-byte compressed encoding."""
        return bytes([3 - self.y.is_even()]) + self.x.to_bytes()

    def to_bytes_uncompressed(self):
        """Convert a point to 65-byte uncompressed encoding."""
        return b'\x04' + self.x.to_bytes() + self.y.to_bytes()

    def to_bytes_xonly(self):
        """Convert (the X coordinate of) a point to 32-byte xonly encoding."""
        return self.x.to_bytes()

    @staticmethod
    def lift_x(x):
        """Take an FE, and return the point with that as X coordinate, and even Y."""
        y = (FE(x)**3 + 7).sqrt()
        if y is None:
            return None
        if not y.is_even():
            y = -y
        return GE(x, y)

    @staticmethod
    def from_bytes(b):
        """Convert a compressed or uncompressed encoding to a point."""
        if len(b) == 33:
            if b[0] != 2 and b[0] != 3:
                return None
            x = FE.from_bytes(b[1:])
            if x is None:
                return None
            r = GE.lift_x(x)
            if r is None:
                return None
            if b[0] == 3:
                r = -r
            return r
        if len(b) == 65:
            if b[0] != 4:
                return None
            x = FE.from_bytes(b[1:33])
            y = FE.from_bytes(b[33:])
            if y**2 != x**3 + 7:
                return None
            return GE(x, y)

    @staticmethod
    def from_bytes_xonly(b):
        """Convert a point given in xonly encoding to a point."""
        assert len(b) == 32
        x = FE.from_bytes(b)
        if x is None:
            return None
        return GE.lift_x(x)

    @staticmethod
    def is_valid_x(x):
        """Determine whether the provided field element is a valid X coordinate."""
        return (FE(x)**3 + 7).is_square()

    def __str__(self):
        """Convert this group element to a string."""
        return f"({self.x},{self.y})"

    def __repr__(self):
        """Get a string representation for this group element."""
        return f"GE(0x{int(self.x):x},0x{int(self.y):x})"

SECP256K1_G = GE(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

class ECPubKey():
    """A secp256k1 public key"""

    def __init__(self):
        """Construct an uninitialized public key"""
        self.p = None

    def set(self, data):
        """Construct a public key from a serialization in compressed or uncompressed format"""
        self.p = GE.from_bytes(data)
        self.compressed = len(data) == 33

    @property
    def is_compressed(self):
        return self.compressed

    @property
    def is_valid(self):
        return self.p is not None

    def get_bytes(self):
        assert self.is_valid
        if self.compressed:
            return self.p.to_bytes_compressed()
        else:
            return self.p.to_bytes_uncompressed()

    def verify_ecdsa(self, sig, msg, low_s=True):
        """Verify a strictly DER-encoded ECDSA signature against this pubkey.

        See https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm for the
        ECDSA verifier algorithm"""
        assert self.is_valid

        # Extract r and s from the DER formatted signature. Return false for
        # any DER encoding errors.
        if (sig[1] + 2 != len(sig)):
            return False
        if (len(sig) < 4):
            return False
        if (sig[0] != 0x30):
            return False
        if (sig[2] != 0x02):
            return False
        rlen = sig[3]
        if (len(sig) < 6 + rlen):
            return False
        if rlen < 1 or rlen > 33:
            return False
        if sig[4] >= 0x80:
            return False
        if (rlen > 1 and (sig[4] == 0) and not (sig[5] & 0x80)):
            return False
        r = int.from_bytes(sig[4:4+rlen], 'big')
        if (sig[4+rlen] != 0x02):
            return False
        slen = sig[5+rlen]
        if slen < 1 or slen > 33:
            return False
        if (len(sig) != 6 + rlen + slen):
            return False
        if sig[6+rlen] >= 0x80:
            return False
        if (slen > 1 and (sig[6+rlen] == 0) and not (sig[7+rlen] & 0x80)):
            return False
        s = int.from_bytes(sig[6+rlen:6+rlen+slen], 'big')

        # Verify that r and s are within the group order
        if r < 1 or s < 1 or r >= GE.ORDER or s >= GE.ORDER:
            return False
        if low_s and s >= GE.ORDER_HALF:
            return False
        z = int.from_bytes(msg, 'big')

        # Run verifier algorithm on r, s
        w = modinv(s, GE.ORDER)
        u1 = z*w % GE.ORDER
        u2 = r*w % GE.ORDER
        R = GE.mmul((SECP256K1_G, u1), (self.p, u2))
        if R is None or (int(R.x) % GE.ORDER) != r:
            return False
        return True

def generate_privkey():
    """Generate a valid random 32-byte private key."""
    return random.randrange(1, GE.ORDER).to_bytes(32, 'big')

def rfc6979_nonce(key):
    """Compute signing nonce using RFC6979."""
    v = bytes([1] * 32)
    k = bytes([0] * 32)
    k = hmac.new(k, v + b"\x00" + key, 'sha256').digest()
    v = hmac.new(k, v, 'sha256').digest()
    k = hmac.new(k, v + b"\x01" + key, 'sha256').digest()
    v = hmac.new(k, v, 'sha256').digest()
    return hmac.new(k, v, 'sha256').digest()

class ECKey():
    """A secp256k1 private key"""

    def __init__(self):
        self.valid = False

    def set(self, secret, compressed):
        """Construct a private key object with given 32-byte secret and compressed flag."""
        assert len(secret) == 32
        secret = int.from_bytes(secret, 'big')
        self.valid = (secret > 0 and secret < GE.ORDER)
        if self.valid:
            self.secret = secret
            self.compressed = compressed

    def generate(self, compressed=True):
        """Generate a random private key (compressed or uncompressed)."""
        self.set(generate_privkey(), compressed)

    def get_bytes(self):
        """Retrieve the 32-byte representation of this key."""
        assert self.valid
        return self.secret.to_bytes(32, 'big')

    @property
    def is_valid(self):
        return self.valid

    @property
    def is_compressed(self):
        return self.compressed

    def get_pubkey(self):
        """Compute an ECPubKey object for this secret key."""
        assert self.valid
        ret = ECPubKey()
        ret.p = self.secret * SECP256K1_G
        ret.compressed = self.compressed
        return ret

    def sign_ecdsa(self, msg, low_s=True, rfc6979=False):
        """Construct a DER-encoded ECDSA signature with this key.

        See https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm for the
        ECDSA signer algorithm."""
        assert self.valid
        z = int.from_bytes(msg, 'big')
        # Note: no RFC6979 by default, but a simple random nonce (some tests rely on distinct transactions for the same operation)
        if rfc6979:
            k = int.from_bytes(rfc6979_nonce(self.secret.to_bytes(32, 'big') + msg), 'big')
        else:
            k = random.randrange(1, GE.ORDER)
        R = k * SECP256K1_G
        r = int(R.x) % GE.ORDER
        s = (modinv(k, GE.ORDER) * (z + self.secret * r)) % GE.ORDER
        if low_s and s > GE.ORDER_HALF:
            s = GE.ORDER - s
        # Represent in DER format. The byte representations of r and s have
        # length rounded up (255 bits becomes 32 bytes and 256 bits becomes 33
        # bytes).
        rb = r.to_bytes((r.bit_length() + 8) // 8, 'big')
        sb = s.to_bytes((s.bit_length() + 8) // 8, 'big')
        return b'\x30' + bytes([4 + len(rb) + len(sb), 2, len(rb)]) + rb + bytes([2, len(sb)]) + sb

def compute_xonly_pubkey(key):
    """Compute an x-only (32 byte) public key from a (32 byte) private key.

    This also returns whether the resulting public key was negated.
    """

    assert len(key) == 32
    x = int.from_bytes(key, 'big')
    if x == 0 or x >= GE.ORDER:
        return (None, None)
    P = x * SECP256K1_G
    return (P.to_bytes_xonly(), not P.y.is_even())

def tweak_add_privkey(key, tweak):
    """Tweak a private key (after negating it if needed)."""

    assert len(key) == 32
    assert len(tweak) == 32

    x = int.from_bytes(key, 'big')
    if x == 0 or x >= GE.ORDER:
        return None
    if not (x * SECP256K1_G).y.is_even():
       x = GE.ORDER - x
    t = int.from_bytes(tweak, 'big')
    if t >= GE.ORDER:
        return None
    x = (x + t) % GE.ORDER
    if x == 0:
        return None
    return x.to_bytes(32, 'big')

def tweak_add_pubkey(key, tweak):
    """Tweak a public key and return whether the result had to be negated."""

    assert len(key) == 32
    assert len(tweak) == 32

    P = GE.from_bytes_xonly(key)
    if P is None:
        return None
    t = int.from_bytes(tweak, 'big')
    if t >= GE.ORDER:
        return None
    Q = t * SECP256K1_G + P
    if Q is None:
        return None
    return (Q.to_bytes_xonly(), not Q.y.is_even())

def verify_schnorr(key, sig, msg):
    """Verify a Schnorr signature (see BIP 340).

    - key is a 32-byte xonly pubkey (computed using compute_xonly_pubkey).
    - sig is a 64-byte Schnorr signature
    - msg is a 32-byte message
    """
    assert len(key) == 32
    assert len(msg) == 32
    assert len(sig) == 64

    P = GE.from_bytes_xonly(key)
    if P is None:
        return False
    r = int.from_bytes(sig[0:32], 'big')
    if r >= FE.SIZE:
        return False
    s = int.from_bytes(sig[32:64], 'big')
    if s >= GE.ORDER:
        return False
    e = int.from_bytes(TaggedHash("BIP0340/challenge", sig[0:32] + key + msg), 'big') % GE.ORDER
    R = GE.mmul((SECP256K1_G, s), (P, GE.ORDER - e))
    if R is None or not R.y.is_even():
        return False
    if r != R.x:
        return False
    return True

def sign_schnorr(key, msg, aux=None, flip_p=False, flip_r=False):
    """Create a Schnorr signature (see BIP 340)."""

    if aux is None:
        aux = bytes(32)

    assert len(key) == 32
    assert len(msg) == 32
    assert len(aux) == 32

    sec = int.from_bytes(key, 'big')
    if sec == 0 or sec >= GE.ORDER:
        return None
    P = sec * SECP256K1_G
    if P.y.is_even() == flip_p:
        sec = GE.ORDER - sec
    t = (sec ^ int.from_bytes(TaggedHash("BIP0340/aux", aux), 'big')).to_bytes(32, 'big')
    kp = int.from_bytes(TaggedHash("BIP0340/nonce", t + P.to_bytes_xonly() + msg), 'big') % GE.ORDER
    assert kp != 0
    R = kp * SECP256K1_G
    k = kp if R.y.is_even() != flip_r else GE.ORDER - kp
    e = int.from_bytes(TaggedHash("BIP0340/challenge", R.to_bytes_xonly() + P.to_bytes_xonly() + msg), 'big') % GE.ORDER
    return R.to_bytes_xonly() + ((k + e * sec) % GE.ORDER).to_bytes(32, 'big')

class TestFrameworkKey(unittest.TestCase):
    def test_schnorr(self):
        """Test the Python Schnorr implementation."""
        byte_arrays = [generate_privkey() for _ in range(3)] + [v.to_bytes(32, 'big') for v in [0, GE.ORDER - 1, GE.ORDER, 2**256 - 1]]
        keys = {}
        for privkey in byte_arrays:  # build array of key/pubkey pairs
            pubkey, _ = compute_xonly_pubkey(privkey)
            if pubkey is not None:
                keys[privkey] = pubkey
        for msg in byte_arrays:  # test every combination of message, signing key, verification key
            for sign_privkey, _ in keys.items():
                sig = sign_schnorr(sign_privkey, msg)
                for verify_privkey, verify_pubkey in keys.items():
                    if verify_privkey == sign_privkey:
                        self.assertTrue(verify_schnorr(verify_pubkey, sig, msg))
                        sig = list(sig)
                        sig[random.randrange(64)] ^= (1 << (random.randrange(8)))  # damaging signature should break things
                        sig = bytes(sig)
                    self.assertFalse(verify_schnorr(verify_pubkey, sig, msg))

    def test_schnorr_testvectors(self):
        """Implement the BIP340 test vectors (read from bip340_test_vectors.csv)."""
        num_tests = 0
        vectors_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'bip340_test_vectors.csv')
        with open(vectors_file, newline='', encoding='utf8') as csvfile:
            reader = csv.reader(csvfile)
            next(reader)
            for row in reader:
                (i_str, seckey_hex, pubkey_hex, aux_rand_hex, msg_hex, sig_hex, result_str, comment) = row
                i = int(i_str)
                pubkey = bytes.fromhex(pubkey_hex)
                msg = bytes.fromhex(msg_hex)
                sig = bytes.fromhex(sig_hex)
                result = result_str == 'TRUE'
                if seckey_hex != '':
                    seckey = bytes.fromhex(seckey_hex)
                    pubkey_actual = compute_xonly_pubkey(seckey)[0]
                    self.assertEqual(pubkey.hex(), pubkey_actual.hex(), "BIP340 test vector %i (%s): pubkey mismatch" % (i, comment))
                    aux_rand = bytes.fromhex(aux_rand_hex)
                    try:
                        sig_actual = sign_schnorr(seckey, msg, aux_rand)
                        self.assertEqual(sig.hex(), sig_actual.hex(), "BIP340 test vector %i (%s): sig mismatch" % (i, comment))
                    except RuntimeError as e:
                        self.fail("BIP340 test vector %i (%s): signing raised exception %s" % (i, comment, e))
                result_actual = verify_schnorr(pubkey, sig, msg)
                if result:
                    self.assertEqual(result, result_actual, "BIP340 test vector %i (%s): verification failed" % (i, comment))
                else:
                    self.assertEqual(result, result_actual, "BIP340 test vector %i (%s): verification succeeded unexpectedly" % (i, comment))
                num_tests += 1
        self.assertTrue(num_tests >= 15) # expect at least 15 test vectors

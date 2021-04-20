import struct
import time
import random


class MD4:

    width = 32
    mask = 0xFFFFFFFF

    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

    def __init__(self, msg=None):
        if msg is None:
            msg = b""

        self.msg = msg

        ml = len(msg) * 8
        msg += b"\x80"
        msg += b"\x00" * (-(len(msg) + 8) % 64)
        msg += struct.pack("<Q", ml)

        self._process([msg[i: i + 64] for i in range(0, len(msg), 64)])

    def __str__(self):
        return self.hexdigest()

    def __eq__(self, other):
        return self.h == other.h

    def bytes(self):
        return struct.pack("<4L", *self.h)

    def hexbytes(self):
        return self.hexdigest().encode

    def hexdigest(self):
        return "".join(f"{value:02x}" for value in self.bytes())

    def _process(self, chunks):
        for chunk in chunks:
            X, h = list(struct.unpack("<16I", chunk)), self.h.copy()

            # Round 1.
            Xi = [3, 7, 11, 19]
            for n in range(16):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                K, S = n, Xi[n % 4]
                hn = h[i] + MD4.F(h[j], h[k], h[l]) + X[K]
                h[i] = MD4.lrot(hn & MD4.mask, S)

            # Round 2.
            Xi = [3, 5, 9, 13]
            for n in range(16):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                K, S = n % 4 * 4 + n // 4, Xi[n % 4]
                hn = h[i] + MD4.G(h[j], h[k], h[l]) + X[K] + 0x5A827999
                h[i] = MD4.lrot(hn & MD4.mask, S)

            # Round 3.
            Xi = [3, 9, 11, 15]
            Ki = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
            for n in range(16):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                K, S = Ki[n], Xi[n % 4]
                hn = h[i] + MD4.H(h[j], h[k], h[l]) + X[K] + 0x6ED9EBA1
                h[i] = MD4.lrot(hn & MD4.mask, S)

            self.h = [((v + n) & MD4.mask) for v, n in zip(self.h, h)]

    @staticmethod
    def F(x, y, z):
        return (x & y) | (~x & z)

    @staticmethod
    def G(x, y, z):
        return (x & y) | (x & z) | (y & z)

    @staticmethod
    def H(x, y, z):
        return x ^ y ^ z

    @staticmethod
    def lrot(value, n):
        lbits, rbits = (value << n) & MD4.mask, value >> (MD4.width - n)
        return lbits | rbits


class ED2K:
    hash = b""

    def __init__(self, msg=None):
        if msg is None:
            msg = b""
        self.msg = msg

        self.compute_hash()

    def compute_hash(self):
        pre_hash = b""
        for i in range(0, len(self.msg), 9728000):
            pre_hash += MD4(self.msg[i:i + 9728000]).bytes()

        self.hash = MD4(pre_hash).bytes() if len(self.msg) > 9728000 or len(self.msg) == 0 else pre_hash

    def hexdigest(self):
        return "".join(f"{value:02x}" for value in self.hash)

    def __str__(self):
        return self.hexdigest()


def main():
    """1 block hash time test"""
    time_start = time.time()
    block = b""
    ED2K(block)
    print("1 block hash time: {}".format(time.time() - time_start))

    """10^3 block hash time test"""
    time_start = time.time()
    block = b""
    for i in range(10 ** 3):
        block = ED2K(block).hash
    print("10^3 block hash time: {}".format(time.time() - time_start))

    """10^6 block hash time test"""
    time_start = time.time()
    block = b""
    for i in range(10 ** 6):
        block = ED2K(block).hash
    print("10^6 block hash time: {}".format(time.time() - time_start))

    """1 mb file hash time test"""
    with open("test/ot_1mb.txt", 'rb') as file:
        time_start = time.time()
        ED2K(file.read())
        print("1 mb hash time: {}".format(time.time() - time_start))

    """100 mb file hash time test"""
    with open("test/ot_100mb.txt", 'rb') as file:
        time_start = time.time()
        ED2K(file.read())
        print("100 mb hash time: {}".format(time.time() - time_start))

    """1 Gb file hash time test"""
    with open("test/ot_1Gb.txt", 'rb') as file:
        time_start = time.time()
        ED2K(file.read())
        print("1 Gb hash time: {}".format(time.time() - time_start))

    """Test on known MD4 hashes"""
    messages = [b"", b"The quick brown fox jumps over the lazy dog", b"The quick brown fox jumps over the lazy cog"]
    for message in messages:
        print("Actual message: {}\n hash: {}".format(message, ED2K(message).hexdigest()))

    """Test of known ED2K hashes"""
    expected = ["d7def262a127cd79096a108e7a9fc138", "194ee9e4fa79b2ee9f8829284c466051", "9a68abb94d13f1e6ea13e968279652d7"]
    for i in range(3):
        with open("test/zeros_{}.txt".format(i + 1), 'rb') as file:
            print("Hashing {}".format(file.name))
            print("Expected: {}".format(expected[i]))
            print("Actual: {}".format(ED2K(file.read()).hexdigest()))
            print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass

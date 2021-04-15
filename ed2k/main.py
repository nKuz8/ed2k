import MD4


import struct


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

    # def __repr__(self):
    #     if self.msg:
    #         return f"{self.__class__.__name__}({self.msg:s})"
    #     return f"{self.__class__.__name__}()"

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

    def __repr__(self):
        if self.msg:
            return f"{self.__class__.__name__}({self.msg:s})"
        return f"{self.__class__.__name__}()"

    def compute_hash(self):
        pre_hash = b""
        for i in range(0, len(self.msg), 9728000):
            pre_hash += MD4(self.msg[i:i + 9728000]).bytes()

        self.hash = MD4(pre_hash).bytes() if len(self.msg) > 9728000 or len(self.msg) == 0 else pre_hash

    def hexdigest(self):
        return "".join(f"{value:02x}" for value in self.hash)


def main():
    # Import is intentionally delayed.
    import sys

    if len(sys.argv) > 1:
        with open(sys.argv[1], 'rb') as input:
            message = input.read()
            print(ED2K(message).hexdigest())
    else:
        messages = [b"", b"The quick brown fox jumps over the lazy dog", b"zeros.txt"]
        known_hashes = [
            "31d6cfe0d16ae931b73c59d7e0c089c0",
            "1bee69a46ba811185c194762abaeae90",
            "59495f401f014f2522c4eae3c9a2b1f8",
        ]

        print("Testing the MD4 class.")
        print()

        for message, expected in zip(messages, known_hashes):
            print("Message: ", message)
            print("Expected:", expected)
            print("Actual:  ", ED2K(message).hexdigest())
            print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass

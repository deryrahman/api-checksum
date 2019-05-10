import struct


class CRC32():
    def __init__(self):
        self.poly = 0xEDB88320

    def __call__(self, data):
        data = bytearray(data)
        crc = 0xFFFFFFFF
        for d in data:
            crc = crc ^ d
            crc = (crc >> 1) ^ (self.poly & -(crc & 1))
            crc = (crc >> 1) ^ (self.poly & -(crc & 1))
            crc = (crc >> 1) ^ (self.poly & -(crc & 1))
            crc = (crc >> 1) ^ (self.poly & -(crc & 1))
            crc = (crc >> 1) ^ (self.poly & -(crc & 1))
            crc = (crc >> 1) ^ (self.poly & -(crc & 1))
            crc = (crc >> 1) ^ (self.poly & -(crc & 1))
            crc = (crc >> 1) ^ (self.poly & -(crc & 1))
        res = 0xFFFFFFFF & ~crc
        res = struct.pack('>I', res)
        return res.hex()


class SHA1():
    def __init__(self):
        self.buffer_md = [
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0,
        ]
        self.k = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]
        self.f = [
            lambda b, c, d: (b & c) | (~b & d),
            lambda b, c, d: b ^ c ^ d,
            lambda b, c, d: (b & c) | (b & d) | (c & d),
            lambda b, c, d: b ^ c ^ d
        ]

    def _roll_left(self, x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def _expand(self, msg):
        """
        msg = bytes
        """
        pad = b'\x80' + b'\x00' * ((56 - ((len(msg) + 1) % 64)) % 64)
        bits_len = struct.pack(b'>Q', len(msg) * 8)
        return msg + pad + bits_len

    def _basic_op(self, a, b, c, d, e, w, k, f):
        """
        a, b, c, d, e = 4 bytes
        """
        res = (f(b, c, d) + e) & 0xFFFFFFFF
        res = (self._roll_left(a, 5) + res) & 0xFFFFFFFF
        res = (w + res) & 0xFFFFFFFF
        res = (k + res) & 0xFFFFFFFF
        b = self._roll_left(b, 30)
        return res, a, b, c, d

    def _h_sha(self, a, b, c, d, e, block):
        """
        block = 64 bytes
        """
        w = []
        a_ori = a
        b_ori = b
        c_ori = c
        d_ori = d
        e_ori = e
        for t in range(80):
            if t < 16:
                w.append(struct.unpack(b'>I', block[t * 4:t * 4 + 4])[0])
            else:
                w.append(
                    self._roll_left(
                        w[t - 16] ^ w[t - 14] ^ w[t - 8] ^ w[t - 3], 1))
            a, b, c, d, e = self._basic_op(a, b, c, d, e, w[t],
                                           self.k[t // 20], self.f[t // 20])

        a = (a_ori + a) & 0xFFFFFFFF
        b = (b_ori + b) & 0xFFFFFFFF
        c = (c_ori + c) & 0xFFFFFFFF
        d = (d_ori + d) & 0xFFFFFFFF
        e = (e_ori + e) & 0xFFFFFFFF
        return a, b, c, d, e

    def __call__(self, msg):
        msg = self._expand(msg)
        a = self.buffer_md[0]
        b = self.buffer_md[1]
        c = self.buffer_md[2]
        d = self.buffer_md[3]
        e = self.buffer_md[4]
        for i in range(len(msg) // 64):
            a, b, c, d, e = self._h_sha(a, b, c, d, e, msg[i * 64:i * 64 + 64])
        res = struct.pack('>IIIII', a, b, c, d, e)
        return res.hex()


class MD5():
    def __init__(self):
        self.buffer_md = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
        self.t = [
            # round 1
            0xD76AA478,
            0xE8C7B756,
            0x242070DB,
            0xC1BDCEEE,
            0xF57C0FAF,
            0x4787C62A,
            0xA8304613,
            0xFD469501,
            0x698098D8,
            0x8B44F7AF,
            0xFFFF5BB1,
            0x895CD7BE,
            0x6B901122,
            0xFD987193,
            0xA679438E,
            0x49B40821,
            # round 2
            0xF61E2562,
            0xC040B340,
            0x265E5A51,
            0xE9B6C7AA,
            0xD62F105D,
            0x02441453,
            0xD8A1E681,
            0xE7D3FBC8,
            0x21E1CDE6,
            0xC33707D6,
            0xF4D50D87,
            0x455A14ED,
            0xA9E3E905,
            0xFCEFA3F8,
            0x676F02D9,
            0x8D2A4C8A,
            # round 3
            0xFFFA3942,
            0x8771F681,
            0x6D9D6122,
            0xFDE5380C,
            0xA4BEEA44,
            0x4BDECFA9,
            0xF6BB4B60,
            0xBEBFBC70,
            0x289B7EC6,
            0xEAA127FA,
            0xD4EF3085,
            0x04881D05,
            0xD9D4D039,
            0xE6DB99E5,
            0x1FA27CF8,
            0xC4AC5665,
            # round 4
            0xF4292244,
            0x432AFF97,
            0xAB9423A7,
            0xFC93A039,
            0x655B59C3,
            0x8F0CCC92,
            0xFFEFF47D,
            0x85845DD1,
            0x6FA87E4F,
            0xFE2CE6E0,
            0xA3014314,
            0x4E0811A1,
            0xF7537E82,
            0xBD3AF235,
            0x2AD7D2BB,
            0xEB86D391
        ]
        # 0: F; 1: G; 2: H; 3: I
        self.f = [
            lambda b, c, d: (b & c) | ((~b) & d), lambda b, c, d: (b & d) |
            (c & (~d)), lambda b, c, d: b ^ c ^ d, lambda b, c, d: c ^ (b | ~d)
        ]
        self.s = ([7, 12, 17, 22] * 4) + ([5, 9, 14, 20] * 4) + \
            ([4, 11, 16, 23] * 4) + ([6, 10, 15, 21] * 4)

    def _roll_left(self, x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def _expand(self, msg):
        """
        msg = bytes
        """
        pad = b'\x80' + b'\x00' * ((56 - ((len(msg) + 1) % 64)) % 64)
        bits_len = struct.pack(b'<Q', len(msg) * 8)
        return msg + pad + bits_len

    def _basic_op(self, a, b, c, d, wt, t, s, f):
        """
        a, b, c, d = 4 bytes
        """
        res = (a + f(b, c, d) + t + wt) & 0xFFFFFFFF
        res = self._roll_left(res, s)
        res = (res + b) & 0xFFFFFFFF
        return d, res, b, c

    def _h_md(self, a, b, c, d, block):
        """
        block = 64 bytes
        """
        w = []
        a_ori = a
        b_ori = b
        c_ori = c
        d_ori = d
        for i in range(64):
            if i < 16:
                w.append(struct.unpack(b'<I', block[i * 4:i * 4 + 4])[0])

            if i < 16:
                k = i
            elif i < 32:
                k = (5 * i + 1) % 16
            elif i < 48:
                k = (3 * i + 5) % 16
            else:
                k = (7 * i) % 16

            a, b, c, d = self._basic_op(a, b, c, d, w[k], self.t[i], self.s[i],
                                        self.f[i // 16])

        a = (a_ori + a) & 0xFFFFFFFF
        b = (b_ori + b) & 0xFFFFFFFF
        c = (c_ori + c) & 0xFFFFFFFF
        d = (d_ori + d) & 0xFFFFFFFF
        return a, b, c, d

    def __call__(self, msg):
        msg = self._expand(msg)
        a = self.buffer_md[0]
        b = self.buffer_md[1]
        c = self.buffer_md[2]
        d = self.buffer_md[3]
        for i in range(len(msg) // 64):
            a, b, c, d = self._h_md(a, b, c, d, msg[i * 64:i * 64 + 64])
        res = struct.pack('<IIII', a, b, c, d)
        return res.hex()


def ck(path, mode):
    c = {'crc32': CRC32(), 'sha1': SHA1(), 'md5': MD5()}.get(mode)

    with open(path, 'rb') as f:
        res = c(f.read())

    return res

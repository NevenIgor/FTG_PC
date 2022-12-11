class BlockCipher(object):
    def __init__(self):

        self.Lvect = bytearray((148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1))

        self.Pi = bytearray((252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233, 119, 240,
                             219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249, 24, 101, 90, 226, 92, 239,
                             33, 129, 28, 60, 66, 139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152,
                             127, 212, 211, 31, 235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206,
                             204, 181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135, 21, 161, 150,
                             41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177, 50, 117, 25, 61, 255, 53,
                             138, 126, 109, 84, 198, 128, 195, 189, 13, 87, 223, 245, 36, 169, 62, 168, 67, 201, 215,
                             121, 214, 246, 124, 34, 185, 3, 224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80,
                             78, 51, 10, 74, 167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 173,
                             69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59, 7, 88, 179, 64, 134,
                             172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137, 225, 27, 131, 73, 76, 63, 248, 254,
                             141, 83, 170, 144, 202, 216, 133, 97, 32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208,
                             190, 229, 108, 82, 89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99,
                             182))

        self.Pi_reverse = bytearray((0xA5, 0x2D, 0x32, 0x8F, 0x0E, 0x30, 0x38, 0xC0, 0x54, 0xE6, 0x9E, 0x39, 0x55, 0x7E,
                                     0x52, 0x91, 0x64, 0x03, 0x57, 0x5A, 0x1C, 0x60, 0x07, 0x18, 0x21, 0x72, 0xA8, 0xD1,
                                     0x29, 0xC6, 0xA4, 0x3F, 0xE0, 0x27, 0x8D, 0x0C, 0x82, 0xEA, 0xAE, 0xB4, 0x9A, 0x63,
                                     0x49, 0xE5, 0x42, 0xE4, 0x15, 0xB7, 0xC8, 0x06, 0x70, 0x9D, 0x41, 0x75, 0x19, 0xC9,
                                     0xAA, 0xFC, 0x4D, 0xBF, 0x2A, 0x73, 0x84, 0xD5, 0xC3, 0xAF, 0x2B, 0x86, 0xA7, 0xB1,
                                     0xB2, 0x5B, 0x46, 0xD3, 0x9F, 0xFD, 0xD4, 0x0F, 0x9C, 0x2F, 0x9B, 0x43, 0xEF, 0xD9,
                                     0x79, 0xB6, 0x53, 0x7F, 0xC1, 0xF0, 0x23, 0xE7, 0x25, 0x5E, 0xB5, 0x1E, 0xA2, 0xDF,
                                     0xA6, 0xFE, 0xAC, 0x22, 0xF9, 0xE2, 0x4A, 0xBC, 0x35, 0xCA, 0xEE, 0x78, 0x05, 0x6B,
                                     0x51, 0xE1, 0x59, 0xA3, 0xF2, 0x71, 0x56, 0x11, 0x6A, 0x89, 0x94, 0x65, 0x8C, 0xBB,
                                     0x77, 0x3C, 0x7B, 0x28, 0xAB, 0xD2, 0x31, 0xDE, 0xC4, 0x5F, 0xCC, 0xCF, 0x76, 0x2C,
                                     0xB8, 0xD8, 0x2E, 0x36, 0xDB, 0x69, 0xB3, 0x14, 0x95, 0xBE, 0x62, 0xA1, 0x3B, 0x16,
                                     0x66, 0xE9, 0x5C, 0x6C, 0x6D, 0xAD, 0x37, 0x61, 0x4B, 0xB9, 0xE3, 0xBA, 0xF1, 0xA0,
                                     0x85, 0x83, 0xDA, 0x47, 0xC5, 0xB0, 0x33, 0xFA, 0x96, 0x6F, 0x6E, 0xC2, 0xF6, 0x50,
                                     0xFF, 0x5D, 0xA9, 0x8E, 0x17, 0x1B, 0x97, 0x7D, 0xEC, 0x58, 0xF7, 0x1F, 0xFB, 0x7C,
                                     0x09, 0x0D, 0x7A, 0x67, 0x45, 0x87, 0xDC, 0xE8, 0x4F, 0x1D, 0x4E, 0x04, 0xEB, 0xF8,
                                     0xF3, 0x3E, 0x3D, 0xBD, 0x8A, 0x88, 0xDD, 0xCD, 0x0B, 0x13, 0x98, 0x02, 0x93, 0x80,
                                     0x90, 0xD0, 0x24, 0x34, 0xCB, 0xED, 0xF4, 0xCE, 0x99, 0x10, 0x44, 0x40, 0x92, 0x3A,
                                     0x01, 0x26, 0x12, 0x1A, 0x48, 0x68, 0xF5, 0x81, 0x8B, 0xC7, 0xD6, 0x20, 0x0A, 0x08,
                                     0x00, 0x4C, 0xD7, 0x74))

        self.power = {}
        self.ret_power = {}
        self.create_lot()
        self.const = self.create_const()

        self.ctr_dict = dict(s=128, syncro='1234567890abcef0')
        self.ofb_dict = dict(s=128, z=2, syncro='1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819')
        self.cbc_dict = dict(z=2, syncro='1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819')
        self.cfb_dict = dict(s=128, m=256, syncro='1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819')

    def create_lot(self):
        a = 1
        self.power[0] = a
        self.ret_power[a] = 0
        oct_x = 0b11000011
        for i in range(1, 255):
            if a << 1 <= 255:
                a = a << 1
            else:
                a = a << 1
                a -= 256
                a = a ^ oct_x
            self.power[i] = a
            self.ret_power[a] = i

    def xor(self, a, b):
        return int.to_bytes(int.from_bytes(a, 'big') ^ int.from_bytes(b, 'big'), 16, byteorder='big')

    def mul_gf2(self, a, b):
        if a == 0 or b == 0:
            return 0
        else:
            return self.power[(self.ret_power[a] + self.ret_power[b]) % 255]

    def l_func(self, vector, mass):
        for _ in range(16):
            k = 0x0
            for i in range(16):
                k = k ^ self.mul_gf2(vector[i], mass[i])
            mass = int.to_bytes(k, 1, 'big') + mass[:-1]
        return mass

    def l_func_rev(self, vector, mass):
        for _ in range(16):
            k = 0x0
            for i in range(16):
                k = k ^ self.mul_gf2(vector[i], mass[-i - 1])
            mass = mass[1:] + int.to_bytes(k, 1, 'big')
        return bytearray(mass)

    def code_block(self, round_key, block):
        X = self.xor(round_key, block)
        S = bytearray(self.Pi[i] % 256 for i in X)
        L = self.l_func(self.Lvect, S)
        return L

    def decode_block(self, round_key, block):
        X = self.xor(round_key, block)
        L = self.l_func_rev(self.Lvect, X)
        S = bytearray(self.Pi_reverse[i] % 256 for i in L)
        return S

    def round(self, keys, block):
        for i in range(9):
            block = self.code_block(keys[i], block)
        R = self.xor(block, keys[9])
        return R

    def round_rev(self, keys, block):
        for i in range(9):
            block = self.decode_block(keys[9 - i], block)
        R = self.xor(block, keys[0])
        return R

    def feistel(self, key, L_sub_block, R_sub_block):
        r = self.code_block(key, L_sub_block)
        X = self.xor(R_sub_block, r)
        return L_sub_block, X

    def feistel_round(self, const, L_key, R_key):
        for i in range(8):
            R_key, L_key = self.feistel(const[i], L_key, R_key)
        return L_key + R_key

    def create_keys(self, master_key):
        round_keys = list()
        round_keys.append(master_key[:16])
        round_keys.append(master_key[16:32])
        for i in range(4):
            r = self.feistel_round(self.const[i * 8: (i * 8) + 8], round_keys[i * 2], round_keys[i * 2 + 1])
            round_keys.append(r[:16])
            round_keys.append(r[16:])
        return round_keys

    def create_const(self):
        c = []
        for i in range(32):
            c.append(self.l_func(self.Lvect, bytearray((0b00, 0b00, 0b00, 0b00, 0b00, 0b00, 0b00, 0b00, 0b00, 0b00,
                                                        0b00, 0b00, 0b00, 0b00, 0b00, i + 1))))
        return c

    def encrypt(self, data, key, mode):
        round_keys = self.create_keys(key)
        result = bytearray()

        if mode == 'ECB':
            num_blocks = len(data) // 16
            for i in range(num_blocks):
                result += self.round(round_keys, data[16 * i: 16 + 16 * i])
            if len(data) % 16 != 0:
                rest = data[num_blocks * 16:] + int.to_bytes(0x80, 1, 'big')\
                       + bytearray(0x00 for i in range(16 - len(data) % 16 - 1))
                result += self.round(round_keys, rest)

        elif mode == 'CTR':
            s = self.ctr_dict['s'] // 8
            ctr = bytearray().fromhex(self.ctr_dict['syncro']) + bytes(s // 2)
            num_blocks = len(data) // s
            for i in range(num_blocks):
                gamma = self.round(round_keys, ctr)
                result += self.xor(gamma, data[s * i: s + s * i])
                ctr = int.to_bytes(int.from_bytes(ctr, 'big') + 1, 16, 'big')
            gamma = self.round(round_keys, ctr)
            for i in range(num_blocks * s, len(data)):
                result += int.to_bytes(data[i] ^ gamma[i % 16], 1, 'big')

        elif mode == 'OFB':
            s = self.ofb_dict['s'] // 8
            num_blocks = len(data) // s
            R = bytearray().fromhex(self.ofb_dict['syncro'])
            for i in range(num_blocks):
                gamma = self.round(round_keys, R[:16])
                result += self.xor(gamma, data[s * i: s + s * i])
                R = R[16:] + gamma
            gamma = self.round(round_keys, R[:16])
            for i in range(num_blocks * s, len(data)):
                result += int.to_bytes(data[i] ^ gamma[i % 16], 1, 'big')

        elif mode == 'CBC':
            R = bytearray().fromhex(self.cbc_dict['syncro'])
            num_blocks = len(data) // 16
            for i in range(num_blocks):
                ent = self.xor(data[16 * i: 16 + 16 * i], R[:16])
                ex = self.round(round_keys, ent)
                result += ex
                R = R[16:] + ex
            if len(data) % 16 != 0:
                rest = data[num_blocks * 16:] + int.to_bytes(0x80, 1, 'big') \
                       + bytearray(0x00 for i in range(16 - len(data) % 16 - 1))
                ent = self.xor(rest, R[:16])
                result += self.round(round_keys, ent)

        elif mode == 'CFB':
            R = bytearray().fromhex(self.cfb_dict['syncro'])
            s = self.cfb_dict['s'] // 8
            num_blocks = len(data) // s
            for i in range(num_blocks):
                gamma = self.round(round_keys, R[:16])
                ex = self.xor(gamma, data[s * i: s + s * i])
                result += ex
                R = R[s:] + ex
            gamma = self.round(round_keys, R[:16])
            for i in range(num_blocks * s, len(data)):
                result += int.to_bytes(data[i] ^ gamma[i % 16], 1, 'big')

        return result

    def decrypt(self, data, key, mode):
        round_keys = self.create_keys(key)
        result = bytearray()

        if mode == 'ECB':
            if len(data) % 16 == 0:
                for i in range(len(data) // 16):
                    result += self.round_rev(round_keys, data[16 * i: 16 + 16 * i])
            i = 1
            while i < 16 and result[-i] == 0:
                i += 1
            if i != 16 and result[-i] == 0x80:
                result = result[:-i]

        elif mode == 'CBC':
            R = bytearray().fromhex(self.cbc_dict['syncro'])
            num_blocks = len(data) // 16
            for i in range(num_blocks):
                ent = self.round_rev(round_keys, data[16 * i: 16 + 16 * i])
                result += self.xor(ent, R[:16])
                R = R[16:] + data[16 * i: 16 + 16 * i]
            i = 1
            while i < 16 and result[-i] == 0:
                i += 1
            if i != 16 and result[-i] == 0x80:
                result = result[:-i]

        elif mode == 'CFB':
            R = bytearray().fromhex(self.cfb_dict['syncro'])
            s = self.cfb_dict['s'] // 8
            num_blocks = len(data) // s
            for i in range(num_blocks):
                ent = self.round(round_keys, R[:16])
                result += self.xor(ent, data[s * i: s + s * i])
                R = R[s:] + data[s * i: s + s * i]
            ent = self.round(round_keys, R[:16])
            for i in range(num_blocks * s, len(data)):
                result += int.to_bytes(data[i] ^ ent[i % s], 1, 'big')

        return result


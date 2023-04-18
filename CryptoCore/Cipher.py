from Crypto.Cipher import AES


class BlockCipher(object):
    def __init__(self):

        AES.key_size = (32,)

        self.ctr_dict = dict(s=128, syncro='1234567890abcef0')
        self.ofb_dict = dict(s=128, z=2, syncro='1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819')
        self.cbc_dict = dict(z=2, syncro='1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819')
        self.cfb_dict = dict(s=128, m=256, syncro='1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819')

    @staticmethod
    def xor(a, b):
        return int.to_bytes(int.from_bytes(a, 'big') ^ int.from_bytes(b, 'big'), 16, byteorder='big')

    def encrypt(self, data, key, mode):
        result = bytearray()

        aes = AES.new(key, AES.MODE_ECB)

        if mode == 'ECB':
            num_blocks = len(data) // 16
            for i in range(num_blocks):
                result += aes.encrypt(data[16 * i: 16 + 16 * i])
            if len(data) % 16 != 0:
                rest = data[num_blocks * 16:] + int.to_bytes(0x80, 1, 'big') \
                       + bytes(0x00 for i in range(16 - len(data) % 16 - 1))
                result += aes.encrypt(rest)

        elif mode == 'CTR':
            s = self.ctr_dict['s'] // 8
            ctr = bytearray().fromhex(self.ctr_dict['syncro']) + bytes(s // 2)
            num_blocks = len(data) // s
            for i in range(num_blocks):
                gamma = aes.encrypt(ctr)
                result += self.xor(gamma, data[s * i: s + s * i])
                ctr = int.to_bytes(int.from_bytes(ctr, 'big') + 1, 16, 'big')
            gamma = aes.encrypt(ctr)
            for i in range(num_blocks * s, len(data)):
                result += int.to_bytes(data[i] ^ gamma[i % 16], 1, 'big')

        elif mode == 'OFB':
            s = self.ofb_dict['s'] // 8
            num_blocks = len(data) // s
            R = bytearray().fromhex(self.ofb_dict['syncro'])
            for i in range(num_blocks):
                gamma = aes.encrypt(R[:16])
                result += self.xor(gamma, data[s * i: s + s * i])
                R = R[16:] + gamma
            gamma = aes.encrypt(R[:16])
            for i in range(num_blocks * s, len(data)):
                result += int.to_bytes(data[i] ^ gamma[i % 16], 1, 'big')

        elif mode == 'CBC':
            R = bytearray().fromhex(self.cbc_dict['syncro'])
            num_blocks = len(data) // 16
            for i in range(num_blocks):
                ent = self.xor(data[16 * i: 16 + 16 * i], R[:16])
                ex = aes.encrypt(ent)
                result += ex
                R = R[16:] + ex
            if len(data) % 16 != 0:
                rest = data[num_blocks * 16:] + int.to_bytes(0x80, 1, 'big') \
                       + bytearray(0x00 for i in range(16 - len(data) % 16 - 1))
                ent = self.xor(rest, R[:16])
                result += aes.encrypt(ent)

        elif mode == 'CFB':
            R = bytearray().fromhex(self.cfb_dict['syncro'])
            s = self.cfb_dict['s'] // 8
            num_blocks = len(data) // s
            for i in range(num_blocks):
                gamma = aes.encrypt(R[:16])
                ex = self.xor(gamma, data[s * i: s + s * i])
                result += ex
                R = R[s:] + ex
            gamma = aes.encrypt(R[:16])
            for i in range(num_blocks * s, len(data)):
                result += int.to_bytes(data[i] ^ gamma[i % 16], 1, 'big')
        return result

    def decrypt(self, data, key, mode):
        aes = AES.new(key, AES.MODE_ECB)
        result = bytearray()

        if mode == 'ECB':
            if len(data) % 16 == 0:
                num_blocks = len(data) // 16
                for i in range(num_blocks):
                    result += aes.decrypt(data[16 * i: 16 + 16 * i])
            i = 1
            while i < 16 and result[-i] == 0:
                i += 1
            if i != 16 and result[-i] == 0x80:
                result = result[:-i]

        elif mode == 'CBC':
            R = bytearray().fromhex(self.cbc_dict['syncro'])
            num_blocks = len(data) // 16
            for i in range(num_blocks):
                ent = aes.decrypt(data[16 * i: 16 + 16 * i])
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
                ent = aes.encrypt(R[:16])
                result += self.xor(ent, data[s * i: s + s * i])
                R = R[s:] + data[s * i: s + s * i]
            ent = aes.encrypt(R[:16])
            for i in range(num_blocks * s, len(data)):
                result += int.to_bytes(data[i] ^ ent[i % s], 1, 'big')
        return result


if __name__ == '__main__':
    bc = BlockCipher()
    data = bytes(16)
    key = bytes(32)
    enc = bc.encrypt(data, key, 'ECB')

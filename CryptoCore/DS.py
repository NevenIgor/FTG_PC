import random
from CryptoCore.EC import ECPoint


class DSGOST:
    def __init__(self, p, a, b, q, p_x, p_y):
        self.p_point = ECPoint(p_x, p_y, a, b, p)
        self.q = q
        self.a = a
        self.b = b
        self.p = p

    # d - priv_key -> int
    # q_point - pub_key -> ECPoint
    def gen_keys(self):
        d = random.randint(1, self.q - 1)
        q_point = d * self.p_point
        return d, q_point

    def sign(self, message, private_key, k=0):
        e = message % self.q
        if e == 0:
            e = 1
        if k == 0:
            k = random.randint(1, self.q - 1)
        r, s = 0, 0
        while r == 0 or s == 0:
            c_point = k * self.p_point
            r = c_point.x % self.q
            s = (r * private_key + k * e) % self.q
        return r, s

    def verify(self, message, sign, public_key):
        e = message % self.q
        if e == 0:
            e = 1
        nu = ECPoint._mod_inverse(e, self.q)
        z1 = (sign[1] * nu) % self.q
        z2 = (-sign[0] * nu) % self.q
        c_point = z1 * self.p_point + z2 * public_key
        r = c_point.x % self.q
        if r == sign[0]:
            return True
        return False

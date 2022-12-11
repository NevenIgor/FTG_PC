from Crypto.Util.number import getPrime


class DHEndpoint():
    def __init__(self, p=None, g=None):
        self.bitsize = 2048

        if not p:
            self.p = getPrime(self.bitsize)
            self.g = getPrime(self.bitsize)
        else:
            self.p = p
            self.g = g

        self.priv_key = getPrime(self.bitsize)

        self.pub_key = pow(self.g, self.priv_key, self.p)

    def generate_full_key(self, pub_key):
        full_key = pow(pub_key, self.priv_key, self.p)
        return full_key

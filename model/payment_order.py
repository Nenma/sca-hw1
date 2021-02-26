from hashlib import sha512


class PaymentOrder:

    def __init__(self, sid, private_key):
        self.order_desc = 'the best product ever'
        self.sid = sid
        self.amount = 42
        self.private_key = private_key
        self.nonce = 1234
        self.signature = self._produce_signature()

    def _produce_signature(self):
        data = bytes(self.order_desc) + self.sid + bytes(self.amount) + bytes(self.nonce)
        hashed_data = int.from_bytes(sha512(data).digest(), 'big')
        return pow(hashed_data, self.private_key.d, self.private_key.n)

from hashlib import sha512


class PaymentOrder:

    def __init__(self, sid, d, n):
        self.order_desc = 'the best product ever'
        self.sid = sid
        self.amount = 42
        self.nonce = 1234
        self.signature = self._produce_signature(d, n)

    def __eq__(self, other):
        return self.order_desc == other.order_desc and self.sid == other.sid and self.amount == other.amount \
               and self.nonce == other.nonce and self.signature == other.signature

    def __hash__(self):
        data = bytes(self.order_desc, encoding='utf-8') + self.sid + bytes(self.amount) + bytes(self.nonce)
        hashed_data = int.from_bytes(sha512(data).digest(), 'big')
        return hashed_data

    def _produce_signature(self, d, n):
        return pow(hash(self), d, n)

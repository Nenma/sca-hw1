from hashlib import sha512


class PaymentInfo:

    def __init__(self, sid, pub_key):
        self.sid = sid
        self.card_number = '1111111111111111'
        self.card_expiry = '12.22'
        self.card_code = '999'
        self.amount = 42
        self.pub_key = pub_key
        self.nonce = 1234
        self.merchant_name = 'M1'

    def __eq__(self, other):
        return self.sid == other.sid and self.card_number == other.card_number and self.card_expiry == other.card_expery \
               and self.card_code == other.card_code and self.amount == other.amount and self.pub_key == other.pub_key \
               and self.nonce == other.nonce and self.merchant_name == other.merchant_name

    def __hash__(self):
        data = self.sid + bytes(self.card_number, encoding='utf8') + bytes(self.card_expiry, encoding='utf8') + \
               bytes(self.card_code, encoding='utf8') + bytes(self.amount) + self.pub_key + bytes(self.nonce) + \
               bytes(self.merchant_name, encoding='utf8')
        hashed_data = int.from_bytes(sha512(data).digest(), 'big')
        return hashed_data

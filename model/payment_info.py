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

import socket
import pickle
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from hashlib import sha512

secret_code = 'sca = awesome'


def pad(input_bytes):
    padding_size = (16 - len(input_bytes)) % 16
    if padding_size == 0:
        padding_size = 16
    padding = (chr(padding_size) * padding_size).encode()
    return input_bytes + padding


def unpad(input_bytes):
    return input_bytes[:-ord(chr(input_bytes[-1]))]


def import_own_key():
    encoded_key = open('rsa/payment_gateway_rsa.bin', 'rb').read()
    key = RSA.import_key(encoded_key, passphrase=secret_code)
    return key


def import_merchant_key():
    encoded_key = open('rsa/merchant_rsa.bin', 'rb').read()
    key = RSA.import_key(encoded_key, passphrase=secret_code)
    return key


def validate_merchant_signature(data, sid, customer_pk, amount):
    merchant_public_key = import_merchant_key().publickey()

    merchant_signature = int.from_bytes(data, 'big')
    merchant_hash = pow(merchant_signature, merchant_public_key.e, merchant_public_key.n)
    pg_payload = sid + unpad(customer_pk) + bytes(amount)
    pg_hash = int.from_bytes(sha512(pg_payload).digest(), 'big')
    print('Merchant signature valid: ', pg_hash == merchant_hash)

    return pg_hash == merchant_hash


def validate_customer_signature(signature, info):
    customer_public_key = RSA.import_key(unpad(info.pub_key))

    customer_signature = int.from_bytes(signature, 'big')
    customer_hash = pow(customer_signature, customer_public_key.e, customer_public_key.n)
    pg_hash = hash(info)
    print('Customer signature valid: ', pg_hash == customer_hash)

    return pg_hash == customer_hash


if __name__ == '__main__':
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 2558)
    sock.bind(server_address)
    print('[Server started at port 2558, listening...]')
    sock.listen(1)

    while True:
        conn, addr = sock.accept()
        try:
            # Phase 4
            d_enc_pi_size = conn.recv(2)
            d_enc_pi_size = int.from_bytes(d_enc_pi_size, 'big')
            d_enc_pi = conn.recv(d_enc_pi_size)

            d_enc_signed_pi_size = conn.recv(2)
            d_enc_signed_pi_size = int.from_bytes(d_enc_signed_pi_size, 'big')
            d_enc_signed_pi = conn.recv(d_enc_signed_pi_size)

            enc_payload_size = conn.recv(2)
            enc_payload_size = int.from_bytes(enc_payload_size, 'big')
            enc_payload = conn.recv(enc_payload_size)

            enc_sk_size = conn.recv(2)
            enc_sk_size = int.from_bytes(enc_sk_size, 'big')
            enc_sk = conn.recv(enc_sk_size)

            # decrypt symmetric key
            own_key = import_own_key()
            sk = PKCS1_OAEP.new(own_key).decrypt(enc_sk)

            # validating merchant signature
            enc_pi = AES.new(sk, AES.MODE_ECB).decrypt(d_enc_pi)
            pi = AES.new(sk, AES.MODE_ECB).decrypt(enc_pi)
            pi = pickle.loads(unpad(pi))
            payload = AES.new(sk, AES.MODE_ECB).decrypt(enc_payload)
            is_merchant_valid = validate_merchant_signature(payload, pi.sid, pi.pub_key, pi.amount)

            # validating customer signature
            enc_signed_pi = unpad(AES.new(sk, AES.MODE_ECB).decrypt(d_enc_signed_pi))
            signed_pi = AES.new(sk, AES.MODE_ECB).decrypt(enc_signed_pi)
            is_customer_valid = validate_customer_signature(signed_pi, pi)

            # Phase 5
            print('Preparing and sending response...')
            if is_merchant_valid and is_customer_valid:
                response = 1
            else:
                response = 0

            # {Resp, SID, SigPG(Resp, Sid, Amount, NC)}PubKM
            enc_response = AES.new(sk, AES.MODE_ECB).encrypt(pad(response.to_bytes(2, 'big')))
            enc_sid = AES.new(sk, AES.MODE_ECB).encrypt(pi.sid)

            payload = bytes(response) + pi.sid + bytes(pi.amount) + bytes(pi.nonce)
            hashed_payload = int.from_bytes(sha512(payload).digest(), 'big')
            signed_payload = pow(hashed_payload, own_key.d, own_key.n)
            enc_signed_payload = AES.new(sk, AES.MODE_ECB).encrypt(signed_payload.to_bytes(128, 'big'))

            merchant_public_key = import_merchant_key().publickey()
            enc_sk = PKCS1_OAEP.new(merchant_public_key).encrypt(sk)

            # sending response back to merchant
            conn.send(len(enc_response).to_bytes(2, 'big'))
            conn.send(enc_response)

            conn.send(len(enc_sid).to_bytes(2, 'big'))
            conn.send(enc_sid)

            conn.send(len(enc_signed_payload).to_bytes(2, 'big'))
            conn.send(enc_signed_payload)

            conn.send(len(enc_sk).to_bytes(2, 'big'))
            conn.send(enc_sk)

        finally:
            conn.close()

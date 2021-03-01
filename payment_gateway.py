import socket
import pickle
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from hashlib import sha512

secret_code = 'sca = awesome'


def unpad(input_bytes):
    return input_bytes[:-ord(chr(input_bytes[-1]))]


def import_own_key():
    encoded_key = open('rsa/payment_gateway_rsa.bin', 'rb').read()
    key = RSA.import_key(encoded_key, passphrase=secret_code)
    return key


def validate_merchant_signature():
    pass


def validate_customer_signature():
    pass


if __name__ == '__main__':
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 2558)
    sock.bind(server_address)
    print(f'Server started at port 2558, listening...')
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

            own_key = import_own_key()
            sk = PKCS1_OAEP.new(own_key).decrypt(enc_sk)
            enc_pi = AES.new(sk, AES.MODE_ECB).decrypt(d_enc_pi)
            pi = AES.new(sk, AES.MODE_ECB).decrypt(enc_pi);
            pi = pickle.loads(pi)



        finally:
            conn.close()

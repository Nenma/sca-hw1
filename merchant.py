from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
import socket
import uuid
from hashlib import sha512


secret_code = 'sca = awesome'


def generate_session_key():
    key_pair = RSA.generate(1024)
    return key_pair


def unpad(input_bytes):
    return input_bytes[:-ord(chr(input_bytes[-1]))]


def import_own_key():
    encoded_key = open('rsa/merchant_rsa.bin', 'rb').read()
    key = RSA.import_key(encoded_key, passphrase=secret_code)
    return key


if __name__ == '__main__':
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 2557)
    sock.bind(server_address)
    print(f'Server started at port 2557, listening...')
    sock.listen(1)

    customer_pk = b''
    sk = b''

    # print(uuid.uuid4())

    while True:
        conn, addr = sock.accept()
        try:

            cpk_size = conn.recv(2)
            cpk_size = int.from_bytes(cpk_size, 'big')
            enc_customer_pk = conn.recv(cpk_size)

            sk_size = conn.recv(2)
            sk_size = int.from_bytes(sk_size, 'big')
            enc_sk = conn.recv(sk_size)

            # decrypt symmetric key
            own_key = import_own_key()
            sk = PKCS1_OAEP.new(own_key).decrypt(enc_sk)

            # decrypt customer public key
            customer_pk = AES.new(sk, AES.MODE_ECB).decrypt(enc_customer_pk)
            customer_pk = unpad(customer_pk)

            # prepare SID and Sig(SID)
            sid = uuid.uuid4().bytes
            print('SID:', sid)
            merchant_hash = int.from_bytes(sha512(sid).digest(), 'big')
            signed_sid = pow(merchant_hash, own_key.d, own_key.n)

            # {SID, SigM(SID)}PubKC
            enc_sid = AES.new(sk, AES.MODE_ECB).encrypt(sid)
            enc_signed_sid = AES.new(sk, AES.MODE_ECB).encrypt(signed_sid.to_bytes(128, 'big'))
            rsa_enc_sk = PKCS1_OAEP.new(RSA.import_key(customer_pk)).encrypt(sk)

            # sending confirmation back to customer
            conn.send(len(enc_sid).to_bytes(2, 'big'))
            conn.send(enc_sid)

            conn.send(len(enc_signed_sid).to_bytes(2, 'big'))
            conn.send(enc_signed_sid)

            conn.send(len(rsa_enc_sk).to_bytes(2, 'big'))
            conn.send(rsa_enc_sk)
        finally:
            conn.close()

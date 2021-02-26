from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
import socket
from hashlib import sha512
from model.payment_info import PaymentInfo
from model.payment_order import PaymentOrder


sk = b'crypto = awesome'
secret_code = 'sca = awesome'


def generate_session_key():
    key_pair = RSA.generate(1024)
    return key_pair


def import_merchant_key():
    encoded_key = open('rsa/merchant_rsa.bin', 'rb').read()
    key = RSA.import_key(encoded_key, passphrase=secret_code)
    return key


def establish_connection():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    merchant_server_address = ('localhost', 2557)
    sock.connect(merchant_server_address)
    return sock


def pad(input_bytes):
    padding_size = (16 - len(input_bytes)) % 16
    if padding_size == 0:
        padding_size = 16
    padding = (chr(padding_size) * padding_size).encode()
    return input_bytes + padding


def validate_signature(sock):
    # receiving confirmation from merchant
    sid_size = sock.recv(2)
    sid_size = int.from_bytes(sid_size, 'big')
    enc_sid = sock.recv(sid_size)

    signed_sid_size = sock.recv(2)
    signed_sid_size = int.from_bytes(signed_sid_size, 'big')
    enc_signed_sid = sock.recv(signed_sid_size)

    sk_size = sock.recv(2)
    sk_size = int.from_bytes(sk_size, 'big')
    enc_sk = sock.recv(sk_size)

    # obtaining SID
    dec_sk = PKCS1_OAEP.new(keys).decrypt(enc_sk)
    sid = AES.new(dec_sk, AES.MODE_ECB).decrypt(enc_sid)
    print('SID:', sid)

    # comparing hashes
    merchant_signature = AES.new(sk, AES.MODE_ECB).decrypt(enc_signed_sid)
    merchant_signature = int.from_bytes(merchant_signature, 'big')
    merchant_hash = pow(merchant_signature, merchant_public_key.e, merchant_public_key.n)
    customer_hash = int.from_bytes(sha512(sid).digest(), 'big')
    print('Signature valid: ', customer_hash == merchant_hash)

    return customer_hash == merchant_hash


if __name__ == '__main__':
    socket = establish_connection()
    keys = generate_session_key()
    public_key = keys.publickey().export_key()

    # ========== SET-UP SUB-PROTOCOL ==========

    public_key = pad(public_key)
    enc_pk = AES.new(sk, AES.MODE_ECB).encrypt(public_key)

    merchant_public_key = import_merchant_key().publickey()
    rsa_enc_sk = PKCS1_OAEP.new(merchant_public_key).encrypt(sk)

    # sending own public key to merchant
    socket.send(len(enc_pk).to_bytes(2, 'big'))
    socket.send(enc_pk)

    socket.send(len(rsa_enc_sk).to_bytes(2, 'big'))
    socket.send(rsa_enc_sk)

    is_signature_valid = validate_signature(socket)

    # =========================================

    if is_signature_valid:
        print('Exchange sub-protocol...')
    else:
        print('Invalid signature!')


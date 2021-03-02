import socket
import pickle
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from hashlib import sha512
from model.payment_info import PaymentInfo
from model.payment_order import PaymentOrder

sk = b'crypto = awesome'
secret_code = 'sca = awesome'
timeout = 5


def generate_session_key():
    key_pair = RSA.generate(1024)
    return key_pair


def import_merchant_key():
    encoded_key = open('rsa/merchant_rsa.bin', 'rb').read()
    key = RSA.import_key(encoded_key, passphrase=secret_code)
    return key


def import_pg_key():
    encoded_key = open('rsa/payment_gateway_rsa.bin', 'rb').read()
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


def unpad(input_bytes):
    return input_bytes[:-ord(chr(input_bytes[-1]))]


def validate_merchant_signature(sock):
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
    print('Merchant signature valid: ', customer_hash == merchant_hash)

    return sid, customer_hash == merchant_hash


def validate_pg_signature(signature, resp, sid, info):
    pg_public_key = import_pg_key().publickey()

    pg_signature = int.from_bytes(signature, 'big')
    pg_hash = pow(pg_signature, pg_public_key.e, pg_public_key.n)
    customer_payload = bytes(resp) + sid + bytes(info.amount) + bytes(info.nonce)
    customer_hash = int.from_bytes(sha512(customer_payload).digest(), 'big')
    print('PG signature valid: ', customer_hash == pg_hash)

    return customer_hash == pg_hash


if __name__ == '__main__':
    socket = establish_connection()
    keys = generate_session_key()
    public_key = keys.publickey().export_key()

    # ========== SET-UP SUB-PROTOCOL ==========
    print('[Starting set-up sub-protocol...]')

    public_key = pad(public_key)
    enc_pk = AES.new(sk, AES.MODE_ECB).encrypt(public_key)

    merchant_public_key = import_merchant_key().publickey()
    rsa_enc_sk = PKCS1_OAEP.new(merchant_public_key).encrypt(sk)

    # sending own public key to merchant
    socket.send(len(enc_pk).to_bytes(2, 'big'))
    socket.send(enc_pk)

    socket.send(len(rsa_enc_sk).to_bytes(2, 'big'))
    socket.send(rsa_enc_sk)

    sid, is_merchant_valid = validate_merchant_signature(socket)

    # =========================================

    if is_merchant_valid:
        start = time.perf_counter()
        print('[Starting exchange sub-protocol...]')

        # Phase 3
        pi = PaymentInfo(sid, public_key)
        pg_public_key = import_pg_key().publickey()
        serialized_pi = pickle.dumps(pi)

        signed_pi = pow(hash(pi), keys.d, keys.n)
        enc_pi = AES.new(sk, AES.MODE_ECB).encrypt(pad(serialized_pi))
        enc_signed_pi = AES.new(sk, AES.MODE_ECB).encrypt(signed_pi.to_bytes(128, 'big'))

        pg_rsa_enc_sk = PKCS1_OAEP.new(pg_public_key).encrypt(sk)

        po = PaymentOrder(sid, keys.d, keys.n)
        serialized_po = pickle.dumps(po)
        enc_po = AES.new(sk, AES.MODE_ECB).encrypt(pad(serialized_po))

        d_enc_pi = AES.new(sk, AES.MODE_ECB).encrypt(enc_pi)
        d_enc_signed_pi = AES.new(sk, AES.MODE_ECB).encrypt(pad(enc_signed_pi))

        m_rsa_enc_sk = PKCS1_OAEP.new(merchant_public_key).encrypt(sk)

        socket.send(len(enc_po).to_bytes(2, 'big'))
        socket.send(enc_po)
        socket.send(len(d_enc_pi).to_bytes(2, 'big'))
        socket.send(d_enc_pi)

        socket.send(len(d_enc_signed_pi).to_bytes(2, 'big'))
        socket.send(d_enc_signed_pi)

        socket.send(len(m_rsa_enc_sk).to_bytes(2, 'big'))
        socket.send(m_rsa_enc_sk)

        # Phase 6
        enc_response_size = socket.recv(2)
        enc_response_size = int.from_bytes(enc_response_size, 'big')
        enc_response = socket.recv(enc_response_size)

        enc_sid_size = socket.recv(2)
        enc_sid_size = int.from_bytes(enc_sid_size, 'big')
        enc_sid = socket.recv(enc_sid_size)

        enc_signed_payload_size = socket.recv(2)
        enc_signed_payload_size = int.from_bytes(enc_signed_payload_size, 'big')
        enc_signed_payload = socket.recv(enc_signed_payload_size)

        enc_sk_size = socket.recv(2)
        enc_sk_size = int.from_bytes(enc_sk_size, 'big')
        enc_sk = socket.recv(enc_sk_size)
        sk = PKCS1_OAEP.new(keys).decrypt(enc_sk)

        finish = time.perf_counter()

        if finish - start < timeout:
            # validating pg signature
            response = AES.new(sk, AES.MODE_ECB).decrypt(enc_response)
            response = unpad(response)
            response = int.from_bytes(response, 'big')
            sid = AES.new(sk, AES.MODE_ECB).decrypt(enc_sid)
            signed_payload = AES.new(sk, AES.MODE_ECB).decrypt(enc_signed_payload)

            is_pg_valid = validate_pg_signature(signed_payload, response, sid, pi)
            if is_pg_valid:
                print('Response from payment gateway: ', response)
            else:
                print('Invalid payment gateway signature!')
        else:
            print('Response timeout!')
    else:
        print('Invalid merchant signature!')

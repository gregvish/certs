from OpenSSL import crypto
from random import randint
import sys

RSA_KEY_LENGTH = 2048
SIGN_HASH_ALGO = 'sha1'
CERT_VALIDITY_PERIOD = 10 * 365 * 24 * 60 * 60

CERT_C = 'IL'
CERT_ST = 'Tel Aviv'
CERT_L = 'Tel Aviv'
CERT_O  = 'TESTING'
CERT_OU = 'TESTING'
CERT_CN = 'TESTING CA'

def _gen_keypair():
    keypair = crypto.PKey()
    keypair.generate_key(crypto.TYPE_RSA, RSA_KEY_LENGTH)
    return keypair

def _gen_selfsigned_cert(key):
    cert = crypto.X509()
    cert.get_subject().C = CERT_C
    cert.get_subject().ST = CERT_ST
    cert.get_subject().L = CERT_L
    cert.get_subject().O = CERT_O
    cert.get_subject().OU = CERT_OU
    cert.get_subject().CN = CERT_CN
    cert.set_serial_number(randint(0, 2**31))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(CERT_VALIDITY_PERIOD)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, SIGN_HASH_ALGO)
    return cert

def main(key_filename, cert_filename):
    key = _gen_keypair()
    open(key_filename, 'w').write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    open(cert_filename, 'w').write(crypto.dump_certificate(crypto.FILETYPE_PEM, _gen_selfsigned_cert(key)))

if __name__ == '__main__':
    main(*sys.argv[1:])

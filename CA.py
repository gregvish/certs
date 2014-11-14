from OpenSSL import crypto
from random import randint
import sys

RSA_KEY_LENGTH = 2048
SIGN_HASH_ALGO = 'sha1'
CERT_VALIDITY_PERIOD = 10 * 365 * 24 * 60 * 60

CERT_C = 'IL'
CERT_ST = 'Tel Aviv'
CERT_L = 'Tel Aviv'
CERT_OU = 'Unit'

def _gen_keypair():
    keypair = crypto.PKey()
    keypair.generate_key(crypto.TYPE_RSA, RSA_KEY_LENGTH)
    return keypair

def _gen_selfsigned_cert(key, cn):
    cert = crypto.X509()
    cert.get_subject().C = CERT_C
    cert.get_subject().ST = CERT_ST
    cert.get_subject().L = CERT_L
    cert.get_subject().OU = CERT_OU
    cert.get_subject().O = cn
    cert.get_subject().CN = cn
    cert.set_serial_number(randint(0, 2**31))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(CERT_VALIDITY_PERIOD)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, SIGN_HASH_ALGO)
    return cert

def main(ca_name):
    key = _gen_keypair()
    open(ca_name + '.pem', 'w').write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    open(ca_name + '.crt', 'w').write(crypto.dump_certificate(crypto.FILETYPE_PEM, _gen_selfsigned_cert(key, ca_name)))

if __name__ == '__main__':
    main(*sys.argv[1:])

from OpenSSL import crypto
from random import randint
import sys

RSA_KEY_LENGTH = 2048
SIGN_HASH_ALGO = 'sha256'
CERT_VALIDITY_PERIOD = 10 * 365 * 24 * 60 * 60

CERT_C = 'US'
CERT_ST = 'NY'
CERT_L = 'NY'
CERT_OU = 'Org'

def _gen_keypair():
    keypair = crypto.PKey()
    keypair.generate_key(crypto.TYPE_RSA, RSA_KEY_LENGTH)
    return keypair

def _gen_signed_cert(key, ca_key, ca_cert, domain, crl_url):
    cert = crypto.X509()
    cert.set_version(2)
    cert.get_subject().C = CERT_C
    cert.get_subject().ST = CERT_ST
    cert.get_subject().L = CERT_L
    cert.get_subject().OU = CERT_OU
    cert.get_subject().O = CERT_OU
    cert.get_subject().CN = domain
    cert.set_serial_number(randint(0, 2**31))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(CERT_VALIDITY_PERIOD)
    cert.set_issuer(ca_cert.get_subject())
    cert.set_pubkey(key)
    extensions = [
        crypto.X509Extension('keyUsage', True, 'digitalSignature, keyEncipherment'),
        crypto.X509Extension('subjectAltName', False, 'DNS: %s' % (domain, )),
        crypto.X509Extension('extendedKeyUsage', False, 'serverAuth',
                             subject=cert, issuer=ca_cert),
        crypto.X509Extension('basicConstraints', False ,'CA:FALSE'),
        crypto.X509Extension('subjectKeyIdentifier' , False , 'hash', subject=cert),
        crypto.X509Extension('authorityKeyIdentifier' , False, 'keyid:always,issuer:always', subject=cert, issuer=ca_cert),
        crypto.X509Extension('crlDistributionPoints', False, 'URI:%s/crl' % (crl_url, )),
        crypto.X509Extension('authorityInfoAccess' , False,
                             'caIssuers;URI:%s/crt,OCSP;URI:%s/ocsp' % (crl_url, crl_url)),
    ]
    cert.add_extensions(extensions)
    cert.sign(ca_key, SIGN_HASH_ALGO)
    return cert

def main(ca_name, site_cn, crl_url='http://google.com'):
    ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(ca_name + '.pem', 'r').read())
    ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(ca_name + '.crt', 'r').read())
    key = _gen_keypair()
    open('site_' + site_cn + '.pem', 'w').write(
        crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    open('site_' + site_cn + '.crt', 'w').write(
        crypto.dump_certificate(crypto.FILETYPE_PEM,
                                _gen_signed_cert(key, ca_key, ca_cert, site_cn, crl_url)))

if __name__ == '__main__':
    main(*sys.argv[1:])

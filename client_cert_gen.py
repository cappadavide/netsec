from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime


def generate_private_rsakey():
    # Generate our key
    key = rsa.generate_private_key(

        public_exponent=65537,
        key_size=2048,
    )


    # Write our key to disk for safe keeping
    with open(str("../client_pkey.pem"), "wb") as f:

        f.write(key.private_bytes(

            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))

    return key


def generate_certificate(issuer,private_key,client_pkey,params):
    # params
    subject = x509.Name([

        x509.NameAttribute(NameOID.COUNTRY_NAME, params['COUNTRY_NAME']),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, params['STATE_OR_PROVINCE_NAME']),
        x509.NameAttribute(NameOID.LOCALITY_NAME, params['LOCALITY_NAME']),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, params['ORGANIZATION_NAME']),
        x509.NameAttribute(NameOID.COMMON_NAME, params['COMMON_NAME']),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        client_pkey.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Our certificate will be valid for 10 days
        datetime.datetime.utcnow() + datetime.timedelta(days=10)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(private_key, hashes.SHA256())  # Sign our certificate with our private key

    with open(str("../certs/client.pem"), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return cert


def set_params(params):
    params['COUNTRY_NAME'] = u"IT"
    params['STATE_OR_PROVINCE_NAME'] = u"Napoli"
    params['LOCALITY_NAME'] = u"San Franciscos"
    params['ORGANIZATION_NAME'] = u"My Company"
    params['COMMON_NAME'] = u"mysiteclient.com"

    return params


def main():
    params = {}

    params = set_params(params)
    client_pkey = generate_private_rsakey()
    from cryptography.hazmat.primitives import serialization

    with open("../privatekey_root.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(

            key_file.read(),

            password=b"passphrase",

        )

    pem_data = open("../certs/cert_root.pem", "rb").read()
    issuer_cert = x509.load_pem_x509_certificate(pem_data)
    issuer = issuer_cert.subject
    cert = generate_certificate(issuer,private_key,client_pkey,params)


main()
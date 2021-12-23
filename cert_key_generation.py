from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime
import ipaddress
one_day = datetime.timedelta(1, 0, 0)

def create_crl(issuer,pkey):

    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(issuer)
    builder = builder.last_update(datetime.datetime.today())
    builder = builder.next_update(datetime.datetime.today() + one_day)
    crl = builder.sign(private_key=pkey, algorithm=hashes.SHA256())

    with open(str("../certs/crl.pem"), "wb") as f:
        f.write(crl.public_bytes(encoding=serialization.Encoding.PEM),
        )
    return crl

def generate_private_rsakey(i,chain_len):
    
    #Generate our key
    key = rsa.generate_private_key(
        
        public_exponent=65537,
        key_size=2048,
    )

    if i == 0: name = "privatekey_root"
    elif i>0 and i<chain_len-1: name = f"privatekey_{i}"
    else: name = "privatekey_server"
    
    #Write our key to disk for safe keeping
    with open(str("../"+name+".pem"), "wb") as f:
        
        f.write(key.private_bytes(
            
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))
        
    return key

def generate_certificate(i,cert_chain,private_key,chain_len,params,issuer_list):

    #params
    subject = x509.Name([
        
        x509.NameAttribute(NameOID.COUNTRY_NAME, params['COUNTRY_NAME']),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, params['STATE_OR_PROVINCE_NAME']),
        x509.NameAttribute(NameOID.LOCALITY_NAME, params['LOCALITY_NAME']),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, params['ORGANIZATION_NAME']),
        x509.NameAttribute(NameOID.COMMON_NAME, params['COMMON_NAME']),
    ])
    issuer_list.append(subject)
    
    #root case
    if i == 0:
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer_list[i]
        ).public_key(
            private_key[i].public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            #Our certificate will be valid for 10 days
            datetime.datetime.utcnow() + datetime.timedelta(days=10)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        ).add_extension(x509.BasicConstraints(ca=True, path_length=None),critical=True,
        ).sign(private_key[i], hashes.SHA256())#Sign our certificate with our private key
        create_crl(issuer_list[i],private_key[i])
    #intermediate CA        
    elif i>0 and i<chain_len-1:

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer_list[i-1]
        ).public_key(
            private_key[i].public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            #Our certificate will be valid for 10 days
            datetime.datetime.utcnow() + datetime.timedelta(days=10)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        ).add_extension(x509.BasicConstraints(ca=True, path_length=None),critical=True,
        ).sign(private_key[i-1], hashes.SHA256())#Sign our certificate with our private key

    #leaf for server, without basic constraints ca=true
    #last certificate
    else:
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer_list[i-1]
        ).public_key(
            private_key[i].public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            #Our certificate will be valid for 10 days
            datetime.datetime.utcnow() + datetime.timedelta(days=10)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost"),x509.IPAddress(ipaddress.IPv4Address('192.168.1.112'))]),
            critical=False,
        ).sign(private_key[i-1], hashes.SHA256())#Sign our certificate with our private key


    if i == 0: name = "cert_root"
    elif i>0 and i<chain_len-1: name = f"cert_{i}"
    else: name = "cert_server"

    if name == "cert_server": path="../" #certificato del server non va hashato
    else: path = "../certs/"
    
    #Write our certificate to disk for safe keeping
    with open(str(path+name+".pem"), "wb") as f:
        
        f.write(cert.public_bytes(serialization.Encoding.PEM))
     
        
    return cert   
    
def set_params(params,i):

    params['COUNTRY_NAME'] = u"US"
    params['STATE_OR_PROVINCE_NAME'] = u"California"
    params['LOCALITY_NAME'] = u"San Francisco"
    params['ORGANIZATION_NAME'] = u"My Company"
    params['COMMON_NAME'] = u"mysite{}.com".format(i)

    return params
    
def main():

    params = {}
    issuer_list = []
    private_key = []
    cert_chain = []
    chain_len = 3

    for i in range(chain_len):
        params = set_params(params,i)
        private_key.append(generate_private_rsakey(i,chain_len))
        cert_chain.append(generate_certificate(i,cert_chain,private_key,chain_len,params,issuer_list))

main()
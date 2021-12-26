#import ssl
import socket
import datetime
import base64
import ssl
import hashlib
from OpenSSL import SSL

from cryptography import x509
from cryptography import exceptions
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat



def parseName(name: x509.Name):
    
    certstr=""
    
    for i in name:
        
        if i.rfc4514_attribute_name == "CN":
            certstr += f"\tCommon Name: {i.value}\n"
            
        elif i.rfc4514_attribute_name == "C":
            certstr += f"\tCountry:{i.value}\n"
            
        elif i.rfc4514_attribute_name == "ST":
            certstr += f"\tState:{i.value}\n"
            
        elif i.rfc4514_attribute_name == "L":
            certstr += f"\tLocality: {i.value}\n"
            
        elif i.rfc4514_attribute_name == "O":
            certstr += f"\tOrganization:{i.value}\n"
            
    return certstr

def parseExtensions(ext: x509.Extensions):
    
    certstr = ""
    
    for e in ext:
        
        if isinstance(e.value,x509.Basisockonstraints):
            
            stringa = f"\n\tPath Length:{e.value.path_length}" if e.value.path_length is not None else ""
            
            certstr += f"\tBasic Constraint:\n\t\tCA:{e.value.ca}{stringa}, critical={e.critical}\n"
            
        elif isinstance(e.value,x509.SubjectAlternativeName):
            
            certstr += "\tSubject Alternative Name:\n\t"
            
            for types in [x509.DNSName,x509.RFC822Name,x509.DirectoryName,x509.IPAddress,x509.UniformResourceIdentifier,x509.RegisteredID,x509.OtherName]:
                
                value = e.value.get_values_for_type(types)
                
                if value:
                    
                    certstr+=f"\t{types.__name__}:{value}\n"

            certstr +=f"\t\tcritical={e.critical}\n"

    return certstr

def parsingString(cert : x509.Certificate):
    
    certstr = ""
    certstr += "Subject:\n"
    certstr += parseName(cert.subject)
    certstr += "Issuer:\n"
    certstr += parseName(cert.issuer)
    
    certstr += f"Certificate Version:\n\t{cert.version.value}\n"
    certstr += f"""Validity Period:\n\t{cert.not_valid_before} - {cert.not_valid_after}\n"""
    certstr += f"Serial Number:\n\t{cert.serial_number}\n"
    certstr += f"Public Key:\n\t{cert.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)}\n"
    certstr += f"Certificate signed with:\n\t{cert.signature_algorithm_oid._name} algorithm\n"
    certstr += f"Signature:\n\t{cert.signature}\n"
    certstr += f"Extensions:\n{parseExtensions(cert.extensions)}"

    return certstr


def checkDigitalSignature(certificates):
    
    for i in range(len(certificates)):
        
        try:
            if certificates[i].subject == certificates[i].issuer:

                certificates[i].public_key().verify(signature=certificates[i].signature,data=certificates[i].tbs_certificate_bytes,padding=padding.PKCS1v15(),algorithm=certificates[i].signature_hash_algorithm)

            else:

                certificates[i+1].public_key().verify(signature=certificates[i].signature,data=certificates[i].tbs_certificate_bytes,padding=padding.PKCS1v15(),algorithm=certificates[i].signature_hash_algorithm)

        except exceptions.InvalidSignature as e:

            return False

    return True


def checkCertValidity(certificate: x509.Certificate):
    
        current_date = datetime.datetime.now()

        return True if current_date >= certificate.not_valid_before and current_date <= certificate.not_valid_after else False

def checkIfRootTrustAnchor(certificates,trustedCertPath):
    
    cert = x509.load_pem_x509_certificate(open(trustedCertPath,"r").read().encode('utf-8'))

    return True if cert == certificates[-1] else False

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('192.168.1.112',4433))
    print(sock.recv(1024).decode())
    sock.send(('starttls\r\n').encode())
    print("prova1")
    print(sock.recv(1024).decode())
    print("prova2")
    ############# Authentication #############
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations("../certs/cert_root.pem")
    context.load_cert_chain(certfile="../client.pem",keyfile="../client_pkey.pem",password=b"passphrase")
    ssock = context.wrap_socket(sock,server_side=False, server_hostname='192.168.1.112')#ssl_version=ssl.PROTOCOL_TLS,certfile="../client.pem",keyfile="../client_pkey.pem",ca_certs="../certs/cert_root.pem")
    print("prova3")
    ssock.send(('helo tester.com\r\n').encode())
    print(ssock.recv(1024).decode())
    ssock.send(('auth login\r\n').encode())
    print(ssock.recv(1024).decode())

    ssock.send((base64.b64encode(('user1').encode())) + ('\r\n').encode())
    print(ssock.recv(1024).decode())

    ssock.send((base64.b64encode(('password1').encode())) + ('\r\n').encode())
    print(ssock.recv(1024).decode())

    ############# EMAIL #############
    ssock.send(("MAIL FROM: <francesco.zuppichini@gmail.com>" + '\r\n').encode())
    print(ssock.recv(1024).decode())
    ssock.send(("RCPT to: <francesco.zuppichini@gmail.com>" + '\r\n').encode())
    print(ssock.recv(1024).decode())
    ssock.send(("DATA" + '\r\n').encode())
    print(ssock.recv(1024).decode())
    # start to send the Data
    ssock.send(("Subject: Test!" + '\r\n').encode())
    ssock.send(("From: francesco.zuppichini@gmail.com" + '\r\n').encode())
    ssock.send(("To: francesco.zuppichini@gmail.com" + '\r\n').encode())
    ssock.send(("Ciaooone" + '\r\n').encode())
    ssock.send(("\r\n.\r\n").encode())
    print(ssock.recv(1024).decode())
    ############# Exit #############
    ssock.send(("QUIT" + '\r\n').encode())
    print(ssock.recv(1024).decode())

    ssock.close()
    sock.close()

"""
def main():
    certificates = []
    hostname = '192.168.1.112'
    port = 4433
    trustedCertPath = "../certs/cert_root.pem"

    #set ssl version and context
    context = SSL.Context(method=SSL.TLSv1_2_METHOD)

    #verify the chain certificate root
    context.set_verify(SSL.VERIFY_PEER)
    #context.use_certificate_file("../certs/client.pem")
    #context.use_privatekey_file("../client_pkey.pem")

    context.load_verify_locations(cafile="../certs/cert_root.pem")


    #create connection between client and server
    conn = SSL.Connection(context, socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    conn.settimeout(5)
    conn.connect((hostname, port))
    conn.setblocking(1)
    #conn.set_connect_state()
    conn.do_handshake()
    conn.set_tlsext_host_name(hostname.encode())

    for cert in conn.get_peer_cert_chain():
        certificates.append(cert.to_cryptography())

    # basic certification
    for cert in certificates:
        print(checkCertValidity(cert))

    print(checkIfRootTrustAnchor(certificates, trustedCertPath))
    print(checkDigitalSignature(certificates))

    print("\nCERTIFICATE PARSING\n")
    for cert in certificates:
        parsingString(cert)
        print("\n")

    conn.close()
"""


main()
"""
def parsingDict(cert: x509.Certificate):
    certdict = {'subject': parseName(cert.subject),'issuer': parseName(cert.issuer),
            'version': cert.version.value, 'validityPeriod':[cert.not_valid_before,cert.not_valid_after],
            'sn': cert.serial_number,'publickey':cert.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo),
            'signalgorithm':cert.signature_algorithm_oid._name,'signature':cert.signature,'extensions':{},'encoded':"casocka"
            }
    for e in cert.extensions:
        if isinstance(e.value,x509.Basisockonstraints):
            certdict["extensions"]["basisockonstraint"] = {'ca':e.value.ca,'pathLen':e.value.path_length,'critical':e.critical}
        elif isinstance(e.value,x509.SubjectAlternativeName):
            certdict["extensions"]["subjectAltName"]={}
            for types in [x509.DNSName,x509.RFC822Name,x509.DirectoryName,x509.IPAddress,x509.UniformResourceIdentifier,x509.RegisteredID,x509.OtherName]:
                value = e.value.get_values_for_type(types)
                if value:
                    certdict["extensions"]["subjectAltName"][types.__name__] = value
            certdict["extensions"]["subjectAltName"]["critical"] = e.critical
    return certdict
"""

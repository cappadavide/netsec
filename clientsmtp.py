import socket
import datetime
import time
import base64
from OpenSSL import SSL
from cryptography import x509
from cryptography import exceptions
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat

hostname = '192.168.1.112'
port = 4433

#funzione per effettuare il parsing dei campi del certificato
def parseName(name: x509.Name):
    
    certstr = ""

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

#funzione per effettuare il parsing delle extension del certificato
def parseExtensions(ext: x509.Extensions):
    
    certstr = ""

    for e in ext:

        if isinstance(e.value, x509.BasicConstraints):

            stringa = f"\n\tPath Length:{e.value.path_length}" if e.value.path_length is not None else ""

            certstr += f"\tBasic Constraint:\n\t\tCA:{e.value.ca}{stringa}, critical={e.critical}\n"

        elif isinstance(e.value, x509.SubjectAlternativeName):

            certstr += "\tSubject Alternative Name:\n\t"

            for types in [x509.DNSName, x509.RFC822Name, x509.DirectoryName, x509.IPAddress,
                          x509.UniformResourceIdentifier, x509.RegisteredID, x509.OtherName]:

                value = e.value.get_values_for_type(types)

                if value:
                    certstr += f"\t{types.__name__}:{value}\n"

            certstr += f"\t\tcritical={e.critical}\n"

    return certstr

#funzione per costruire il parsing completo dei certificati
def parsingString(cert: x509.Certificate):
    
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


#funzione per effettuare il primo punto della Basic Certification Validation:
#controllare la validità della signature del certificato di root
def checkDigitalSignature(certificates):
    
    for i in range(len(certificates)):
        try:
            if certificates[i].subject == certificates[i].issuer:
                certificates[i].public_key().verify(signature=certificates[i].signature,
                                                    data=certificates[i].tbs_certificate_bytes,
                                                    padding=padding.PKCS1v15(),
                                                    algorithm=certificates[i].signature_hash_algorithm)

            else:

                certificates[i + 1].public_key().verify(signature=certificates[i].signature,
                                                        data=certificates[i].tbs_certificate_bytes,
                                                        padding=padding.PKCS1v15(),
                                                        algorithm=certificates[i].signature_hash_algorithm)

        except exceptions.InvalidSignature as e:

            return False

    return True


#funzione per effettuare il secondo punto della Basic Certification Validation:
#controllare la validità di ogni certificato dal punto di vista temporale(certificato scaduto o valido)
def checkCertValidity(certificate: x509.Certificate):
    
    current_date = datetime.datetime.now()

    return True if current_date >= certificate.not_valid_before and current_date <= certificate.not_valid_after else False


#funzione per effettuare il terzo punto della Basic Certification Validation:
#controllare la validità del certificato di root per capire se è una trust anchor
def checkIfRootTrustAnchor(certificates, trustedCertPath):
    
    cert = x509.load_pem_x509_certificate(open(trustedCertPath, "r").read().encode('utf-8'))

    return True if cert == certificates[-1] else False


def main():
    
    certificates = []
    trustedCertPath = "../certs/cert_root.pem"

    context = SSL.Context(method=SSL.TLS_METHOD)
    
    context.use_certificate_file("../client.pem")
    context.use_privatekey_file("../client_pkey.pem")
    context.load_verify_locations(cafile="../certs/cert_root.pem")
    context.set_verify(SSL.VERIFY_PEER)#abilito il controllo dei certificati

    start = time.time()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    #creo una connessione tra client e server
    sock.connect((hostname, port))
    
    print(sock.recv(1024).decode())
    sock.send(('helo tester.com\r\n').encode())
    print(sock.recv(1024).decode())
    sock.send(('starttls\r\n').encode())
    print(sock.recv(1024).decode())

    ssock = SSL.Connection(context, socket=sock)
    ssock.set_connect_state()#serve a far capire che questo peer è il client
    
    try:
        ssock.do_handshake()#inizio dell'handshake

        for cert in ssock.get_peer_cert_chain():
            certificates.append(cert.to_cryptography())

        #basic certification validation
        print("Validità temporale certificati:")
        for cert in certificates:
            print(checkCertValidity(cert))
        print("\n")

        print(f"Root è una trust anchor: {checkIfRootTrustAnchor(certificates, trustedCertPath)}")
        print(f"Signature valida: {checkDigitalSignature(certificates)}")

        print("\nCERTIFICATE PARSING\n")
        for cert in certificates:
            print(parsingString(cert))

        ssock.send(('ehlo tester.com\r\n').encode())
        print(ssock.recv(1024).decode())
        ssock.send(('AUTH LOGIN\r\n').encode())
        print(ssock.recv(1024).decode())

        ssock.send((base64.b64encode(('user1').encode())) + ('\r\n').encode())
        print(ssock.recv(1024).decode())

        ssock.send((base64.b64encode(('password1').encode())) + ('\r\n').encode())
        print(ssock.recv(1024).decode())

        ssock.send(("MAIL FROM: <davi.somma@studenti.unina.it>" + '\r\n').encode())
        print(ssock.recv(1024).decode())
        ssock.send(("RCPT to: <i.tieri@studenti.unina.it>" + '\r\n').encode())
        print(ssock.recv(1024).decode())
        ssock.send(("DATA" + '\r\n').encode())
        print(ssock.recv(1024).decode())

        ssock.send(("Subject: Test!" + '\r\n').encode())
        ssock.send(("From: davi.somma@studenti.unina.it" + '\r\n').encode())
        ssock.send(("To: i.tieri@studenti.unina.it" + '\r\n').encode())
        ssock.send(("Ciao!" + '\r\n').encode())
        ssock.send(("\r\n.\r\n").encode())
        print(ssock.recv(1024).decode())

        ssock.send(("QUIT" + '\r\n').encode())
        print(ssock.recv(1024).decode())

        ssock.close()
        sock.close()
        end = time.time()
        
        print(f"Execution time: {end - start}")
        
    except SSL.Error as e:
        
        print(f"Certificato del server non valido!\n{e}")

main()

import socket
import datetime
from time import sleep
import glob

import aiosmtpd
from OpenSSL import SSL
import asyncio

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP, Session, Envelope
from aiosmtpd.handlers import Sink
import ssl
from aiosmtpd.smtp import AuthResult, LoginPassword


auth_db = {
    b"user1": b"password1",
    b"user2": b"password2",
    b"user3": b"password3",
}
class CustomHandler:
    async def handle_DATA(self, session, envelope):
        peer = session.peer
        mail_from = envelope.mail_from
        rcpt_tos = envelope.rcpt_tos
        data = envelope.content  # type: bytes
        # Process message data...
        print('peer:' + str(peer))
        print('mail_from:' + str(mail_from))
        print('rcpt_tos:' + str(rcpt_tos))
        print('data:' + str(data))
        return '250 OK'
    async def handle_AUTH(server: aiosmtpd.smtp.SMTP, session: Session, envelope: Envelope,auth_data):
        # For this simple example, we'll ignore other parameters
        assert isinstance(auth_data, LoginPassword)
        username = auth_data.login
        password = auth_data.password
        # If we're using a set containing tuples of (username, password),
        # we can simply use `auth_data in auth_set`.
        # Or you can get fancy and use a full-fledged database to perform
        # a query :-)
        if auth_db.get(username) == password:
            return AuthResult(success=True)
        else:
            return AuthResult(success=False, handled=False)

class Authenticator:
    def __init__(self):
        self.auth_db = auth_db
    def __call__(self, server, session, envelope, mechanism, auth_data):
        fail_nothandled = AuthResult(success=False, handled=False)
        if mechanism not in (b"LOGIN", b"PLAIN"):
            return fail_nothandled
        if not isinstance(auth_data, LoginPassword):
            return fail_nothandled
        username = auth_data.login
        password = auth_data.password
        if auth_db.get(username) == password:
            return AuthResult(success=True)
        else:
            return fail_nothandled


# Name can actually be anything
def authenticator_func(server, session, envelope, mechanism, auth_data):
    # For this simple example, we'll ignore other parameters
    assert isinstance(auth_data, LoginPassword)
    username = auth_data.login
    password = auth_data.password
    # If we're using a set containing tuples of (username, password),
    # we can simply use `auth_data in auth_set`.
    # Or you can get fancy and use a full-fledged database to perform
    # a query :-)
    if auth_db.get(username) == password:
        return AuthResult(success=True)
    else:
        return AuthResult(success=False, handled=False)

#loop = asyncio.get_event_loop()
ca_certs = []
for i in glob.glob("../certs/*.pem"):
    if "crl" not in i:
        ca_certs.append(i)
print(ca_certs)
ca_certs.append("../cert_server.pem")
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
print(context.minimum_version,context.maximum_version)


#context.verify_mode = ssl.CERT_REQUIRED
#print(context.protocol)
#context =ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)                   #capath="../certs")
context.load_verify_locations(cafile=None,capath="../certs")
context.load_cert_chain(certfile="../cert_server.pem",keyfile="../privatekey_server.pem",password=b"passphrase")



class MyController(Controller):
    def factory(self):
        smtp = SMTP(self.handler,authenticator=authenticator_func,hostname=self.hostname,timeout=300,decode_data=True,auth_required=True, require_starttls=True,loop=self.loop)
        smtp.tls_context = context
        return smtp
controller = MyController(Sink,hostname='192.168.1.112',port=4433)
controller.start()
input('SMTP server running. Press Return to stop server and exit.')
controller.stop()




"""
context = SSL.Context(method = SSL.TLSv1_2_METHOD)
context.set_verify(SSL.VERIFY_PEER or SSL.VERIFY_FAIL_IF_NO_PEER_CERT)

context.load_verify_locations(cafile=None,capath="../certs")
context.use_certificate_file("../cert_server.pem")
context.use_privatekey_file("../privatekey_server.pem")
sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
conn = SSL.Connection(context,socket=sock)
conn.bind(('', 4433))
conn.listen(5)
print("Sono in ascolto...\n")

server, addr = conn.accept()

server_ssl = SSL.Connection(context, server)
server_ssl.set_accept_state()
server_ssl.do_handshake()

server.close()
"""
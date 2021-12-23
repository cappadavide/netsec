import socket
import datetime
from time import sleep
import glob
from OpenSSL import SSL
import asyncio

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP
from aiosmtpd.handlers import Sink
import ssl
#loop = asyncio.get_event_loop()
ca_certs = []
for i in glob.glob("../certs/*.pem"):
    if "crl" not in i:
        ca_certs.append(i)
print(ca_certs)
ca_certs.append("../cert_server.pem")

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH,capath="../certs")
context.load_cert_chain(certfile="../cert_server.pem",keyfile="../privatekey_server.pem",password=b"passphrase")
context.load_verify_locations(cafile=None,capath="../certs")
class MyController(Controller):
    def factory(self):
        return SMTP(self.handler,hostname=self.hostname,timeout=300,decode_data=True,auth_required=True,tls_context=context, require_starttls=True,loop=self.loop)

controller = MyController(Sink(),hostname='192.168.1.112',port=4433)
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
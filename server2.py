import socket
import datetime
from time import sleep

from OpenSSL import SSL
import asyncio

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP
from aiosmtpd.handlers import Sink
import ssl

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

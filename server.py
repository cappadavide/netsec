import socket
import datetime
from OpenSSL import SSL

context = SSL.Context(method = SSL.TLSv1_METHOD)
context.set_verify(SSL.VERIFY_PEER)
context.load_verify_locations(cafile=None,capath="../certs")
context.use_certificate_file("../cert_server.pem")
context.use_privatekey_file("../privatekey_server.pem")
sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
conn = SSL.Connection(context,socket=sock)

conn.bind(('', 4433))
conn.listen(5)
print("Sono in ascolto...\n")

server, addr = conn.accept()

server_ssl = SSL.Connection(context, server)
server_ssl.set_accept_state()
server_ssl.do_handshake()
server.close()

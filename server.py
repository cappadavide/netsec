import socket
import datetime
from OpenSSL import SSL

context = SSL.Context(method = SSL.TLSv1_1_METHOD)
context.load_verify_locations(cafile=None,capath="../certs")
sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
conn = SSL.Connection(context,socket=sock)
conn.bind(('127.0.0.1', 4433))
conn.listen(5)
print("Sono in ascolto...\n")
conn, addr = conn.accept()


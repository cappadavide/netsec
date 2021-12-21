import socket
import datetime
from OpenSSL import SSL

context = SSL.Context(method = SSL.TLSv1_1_METHOD)
context.load_verify_locations(cafile=None,capath="../certs")
sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
sock.bind(('192.168.1.112', 4433))
sock.listen(5)
conn = SSL.Connection(context,socket=sock)
conn, addr = conn.accept()
print("Sono in ascolto...\n")

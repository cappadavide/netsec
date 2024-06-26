import ssl
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP
from aiosmtpd.handlers import Sink
from aiosmtpd.smtp import AuthResult, LoginPassword

hostname = '192.168.1.112'
port = 4433

#database per effettuare l'autenticazione smtp client/server
auth_db = {
        
    b"user1": b"password1",
    b"user2": b"password2",
    b"user3": b"password3",
}


#funzione per definire un autenticatore per effettuare l'autenticazione smtp
def authenticator_func(server, session, envelope, mechanism, auth_data):
    
    assert isinstance(auth_data, LoginPassword)
    username = auth_data.login
    password = auth_data.password
    
    if auth_db.get(username) == password:
        return AuthResult(success=True)
    else:
        return AuthResult(success=False, handled=False)


context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_verify_locations(cafile=None,capath="../certs")
context.load_cert_chain(certfile="../cert_server.pem",keyfile="../privatekey_server.pem",password=b"passphrase")

#creo un controller (handler) per eseguire il server smtp su di un thread separato
#e per gestire i pacchetti smtp con azione di default = sink(scartare)
class MyController(Controller):
    
    def factory(self):
        
        smtp = SMTP(self.handler,authenticator=authenticator_func,hostname=self.hostname,timeout=300,decode_data=True,auth_required=True, require_starttls=True,loop=self.loop)
        smtp.tls_context = context
        return smtp
    
def main():
    
    controller = MyController(Sink,hostname=hostname,port=port)

    controller.start()
    input('SMTP server running. Press Return to stop server and exit.')
    controller.stop()

main()

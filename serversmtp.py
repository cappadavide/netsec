from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP
from aiosmtpd.handlers import Sink
import ssl
from aiosmtpd.smtp import AuthResult, LoginPassword


auth_db = {
    b"user1": b"password1",
    b"user2": b"password2",
    b"user3": b"password3",
}


# Name can actually be anything
def authenticator_func(server, session, envelope, mechanism, auth_data):
    # For this simple example, we'll ignore other parameters
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



class MyController(Controller):
    def factory(self):
        smtp = SMTP(self.handler,authenticator=authenticator_func,hostname=self.hostname,timeout=300,decode_data=True,auth_required=True, require_starttls=True,loop=self.loop)
        smtp.tls_context = context
        return smtp

controller = MyController(Sink,hostname='192.168.1.112',port=4433)
controller.start()
input('SMTP server running. Press Return to stop server and exit.')
controller.stop()




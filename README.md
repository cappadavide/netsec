# Network Security Project

## Description
The objective of this project is to illustrate one of the many possible application scenarios of the **Secure Socket Layer** (SSL) protocol suite, namely its use in the **Simple Mail Transfer Protocol** (SMTP) application layer protocol in a client/server context.
SMTPS is the "secure" version of SMTP, proposed in the [RFC 4207](https://datatracker.ietf.org/doc/html/rfc3207.html) specification. This extension of the protocol allows for the use of TLS in client-server communication, offering the full range of benefits that this technology provides.
In particular, the extension of SMTP in which the AUTH command is present was considered (see [RFC 4954](https://datatracker.ietf.org/doc/html/rfc4954)).
Subsequently, an SMTP client and server were implemented in a simulated and controlled environment. The client was implemented in both Python and Java to facilitate a comparative analysis of its performance. The server was implemented using mainly the [aiosmtpd](https://github.com/aio-libs/aiosmtpd) library and executed on a Raspberry Pi 3B+. Additionally, dummy certificates were generated to simulate a proper handshake between the client and server, utilizing the `cryptography` library. The following scheme was used:
<p align="center">
  <img src="https://github.com/cappadavide/netsec/assets/58134090/32f12c3b-7eda-4428-9a92-b1d936f7e664" alt="CertificatesScheme"/>
</p>

## Authors
[cappadavide](https://github.com/cappadavide)
i.tieri

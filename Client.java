import java.net.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.io.*;
import javax.net.ssl.*;
import java.util.Base64;
import java.util.Date;
import java.nio.charset.StandardCharsets;

public class Client{

    public static boolean checkValidity(X509Certificate c){
        Date date=new Date();
        return date.compareTo(c.getNotBefore()) >= 0 && date.compareTo(c.getNotAfter()) <=0;
    }
    public static boolean checkIfRootTrustAnchor(X509Certificate [] c,InputStream trustcert) throws Exception{
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) fact.generateCertificate(trustcert);
        return cert.equals(c[c.length-1]);
    }
    public static boolean checkDigitalSignature(X509Certificate [] certificates){
        for(int i=0; i<certificates.length;i++){
            try {
                if (certificates[i].getSubjectX500Principal().equals(certificates[i].getIssuerX500Principal())){
                    certificates[i].verify(certificates[i].getPublicKey());
                }
                else{
                    certificates[i].verify(certificates[i+1].getPublicKey());
                }

            } catch (Exception e) {
                return false;
            
            }
        }
        return true;
    }

    public static void main(String[] args) {

        File file = new File("../client.pkcs12");
        File fileks = new File("../truststore.ks");
        try
        {
            InputStream in = new FileInputStream(file);
            InputStream in2 = new FileInputStream(fileks);
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            String pw = "passphrase1";
            keystore.load(in,pw.toCharArray());
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keystore, pw.toCharArray());
            KeyStore keystore_ca = KeyStore.getInstance("JKS");
            String pwks = "keystore";
            keystore_ca.load(in2, pwks.toCharArray());
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(keystore_ca);
            Date start=new Date();
            Socket sock = new Socket("192.168.1.112", 4433);
            InputStream inn = sock.getInputStream();
            OutputStream outt = sock.getOutputStream();
            BufferedReader br = new BufferedReader(new InputStreamReader(inn));
            PrintWriter pwr  = new PrintWriter(new OutputStreamWriter(outt), true);
            if (inn == null || outt == null) {
                System.out.println("Failed to open streams to socket.");
            }
        
            System.out.println(br.readLine());
            pwr.println("HELO tester.com");
            System.out.println(br.readLine());
            pwr.println("STARTTLS");
            System.out.println(br.readLine());
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
            SSLSocketFactory ssf = sslContext.getSocketFactory();
            //SSLSocket ssock = (SSLSocket) ssf.createSocket("192.168.1.112",4433);
            SSLSocket ssock = (SSLSocket) ssf.createSocket(sock,"192.168.1.112", 4433, false);
            ssock.setUseClientMode(true);

            inn = ssock.getInputStream();
            outt = ssock.getOutputStream();
            br = new BufferedReader(new InputStreamReader(inn));
            pwr  = new PrintWriter(new OutputStreamWriter(outt), true);
            if (inn == null || outt == null) {
                System.out.println("Failed to open streams to socket.");
            }

            System.out.println("Sono qui yeee1\n");
            ssock.startHandshake();

            SSLSession session = ssock.getSession();

            System.out.println("Lunghezza:"+session.getPeerCertificates().length); 
            X509Certificate [] certificates = (X509Certificate []) session.getPeerCertificates();
            File trustPath = new File("../certs/cert_root.pem");
            for (Certificate i: certificates){
                System.out.println(Client.checkValidity((X509Certificate)i));
            }
            System.out.println("CheckRoot:"+Client.checkIfRootTrustAnchor(certificates,(InputStream)new FileInputStream(trustPath)));
            System.out.println("CheckSig:"+Client.checkDigitalSignature(certificates));



            System.out.print("Sono qui yeee\n");
            pwr.println("EHLO tester.com");
            System.out.println(br.readLine());
            pwr.println("AUTH LOGIN");
            System.out.println(br.readLine());
            pwr.println(Base64.getEncoder().encodeToString("user1".getBytes()));
            System.out.println(br.readLine());
            pwr.println(Base64.getEncoder().encodeToString("password1".getBytes()));
            System.out.println(br.readLine());
            
            //EMAIL
            pwr.println("MAIL FROM: <francesco.zuppichini@gmail.com>");
            System.out.println(br.readLine());
            pwr.println("RCPT to: <francesco.zuppichini@gmail.com");
            System.out.println(br.readLine());
            pwr.println("DATA");
            System.out.println(br.readLine());
            //
            pwr.println("Subject: Test!");
            pwr.println("From: francesco.zuppichini@gmail.com");
            pwr.println("To: francesco.zuppichini@gmail.com");
            pwr.println("Ciaooooone");
            pwr.println(".");
            System.out.println(br.readLine());
            pwr.println("QUIT");
            System.out.println(br.readLine());
            br.close();
            pwr.close();
            ssock.close();  
            sock.close();

            
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        

        

    }
}

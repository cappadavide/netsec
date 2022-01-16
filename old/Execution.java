import java.net.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.io.*;
import java.util.Scanner;
import javax.net.ssl.*;
import java.util.Base64;
import java.util.Date;
import java.util.Calendar;

class Client2{
    private File trustStore;
    private File keystore;
    private File trustPEM;
    private KeyManagerFactory kmf;
    private TrustManagerFactory tmf;
    protected long startTime;
    protected long estimatedTime;
    private Socket sock;
    
    public Client2(String tPath,String kPath,String tPEMPath){ //Costruttore della classe Client e inizializzazione dei file
        this.trustStore = new File(tPath);
        this.keystore =  new File(kPath);
        this.trustPEM = new File(tPEMPath);
    }

    private boolean loadCerts(){
        try{
            InputStream in = new FileInputStream(keystore);
            InputStream in2 = new FileInputStream(trustStore);
            KeyStore keystore = KeyStore.getInstance("PKCS12"); //Caricamento del proprio certificato
            Scanner scan= new Scanner(System.in);
            System.out.println("Inserire password keystore:");
            String pw= scan.nextLine();
            keystore.load(in,pw.toCharArray());
            this.kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            this.kmf.init(keystore, pw.toCharArray());
            KeyStore keystore_ca = KeyStore.getInstance("JKS"); //Caricamento delle autorità trusted
            System.out.println("Inserire password truststore:");
            String pwks= scan.nextLine();
            keystore_ca.load(in2, pwks.toCharArray());
            this.tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            this.tmf.init(keystore_ca);
            scan.close();
        }
        catch(Exception e){
            System.out.println(e.toString());
            return false;
        }
        return true;

    }

    public boolean connect(String ip,int port){
        if (loadCerts()){ //Carica correttamente tutti i certificati
            try {
                this.startTime = System.nanoTime();
                this.sock = new Socket(ip, port); //Stabilisce una connessione con il server

            } catch (Exception e) {
                return false;
            }
        }
        else
            return false;
        
        return true;
    }

    public boolean startSMTPClient(String hostname, int port){
        try {
            InputStream inn = this.sock.getInputStream();
            OutputStream outt = this.sock.getOutputStream();
            BufferedReader br = new BufferedReader(new InputStreamReader(inn));
            PrintWriter pwr  = new PrintWriter(new OutputStreamWriter(outt), true);
            if (inn == null || outt == null) {
                System.out.println("Failed to open streams to socket.");
            }
            /* Inizio comunicazione SMTP*/
            System.out.println(br.readLine());
            pwr.println("HELO tester.com");
            System.out.println(br.readLine());

            pwr.println("STARTTLS");
            System.out.println(br.readLine());
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom()); //Inizializzazione del contesto SSL
            SSLSocketFactory ssf = sslContext.getSocketFactory();

            SSLSocket ssock = (SSLSocket) ssf.createSocket(sock,hostname, port, false);
            ssock.setUseClientMode(true);

            inn = ssock.getInputStream();
            outt = ssock.getOutputStream();
            br = new BufferedReader(new InputStreamReader(inn));
            pwr  = new PrintWriter(new OutputStreamWriter(outt), true);
            if (inn == null || outt == null) {
                System.out.println("Failed to open streams to socket.");
            }


            ssock.startHandshake(); //Tentativo di handshake con il server

            SSLSession session = ssock.getSession();
            
            /*Inizio Basic Certificate Validation*/


            /* Controllare la validità di ogni certificato dal punto di vista temporale(certificato scaduto o valido) */
            X509Certificate [] certificates = (X509Certificate []) session.getPeerCertificates();
            for (Certificate i: certificates){
                System.out.println(Client2.checkValidity((X509Certificate)i));
            }
            /* Controllare la validità del certificato di root per capire se è una trust anchor */
            System.out.println("CheckRoot:"+Client2.checkIfRootTrustAnchor(certificates,(InputStream)new FileInputStream(this.trustPEM)));
            /* Controllare la validità della signature del certificato di root */
            System.out.println("CheckSig:"+Client2.checkDigitalSignature(certificates));

            /*Fine Basic Certificate Validation*/
            pwr.println("EHLO tester.com");
            System.out.println(br.readLine());
            pwr.println("AUTH LOGIN");
            System.out.println(br.readLine());
            pwr.println(Base64.getEncoder().encodeToString("user1".getBytes()));
            System.out.println(br.readLine());
            pwr.println(Base64.getEncoder().encodeToString("password1".getBytes()));
            System.out.println(br.readLine());
            
            //EMAIL
            pwr.println("MAIL FROM: <davi.somma@studenti.unina.it>");
            System.out.println(br.readLine());
            pwr.println("RCPT to: <i.tieri@studenti.unina.it>");
            System.out.println(br.readLine());
            pwr.println("DATA");
            System.out.println(br.readLine());

            pwr.println("Subject: Test!");
            pwr.println("From: davi.somma@studenti.unina.it");
            pwr.println("To: i.tieri@studenti.unina.it");
            pwr.println("Ciao!");
            pwr.println(".");
            System.out.println(br.readLine());
            pwr.println("QUIT");
            System.out.println(br.readLine());
            br.close();
            pwr.close();
            ssock.close();  
            sock.close();
            this.estimatedTime = System.nanoTime() - startTime;
            System.out.println("Time in nanoseconds: "+(this.estimatedTime));

        } catch (Exception e) {
            System.out.println(e.toString());
            return false;
        }
        return true;
    
    }

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

}

public class Execution{
    public static void main(String[] args) {
        String hostname = "192.168.1.112";
        int port = 4433;
        Client2 client = new Client2("../truststore.ks","../client.pkcs12","../certs/cert_root.pem"); 
        client.connect(hostname,port);
        client.startSMTPClient(hostname,port);
    }
    
}
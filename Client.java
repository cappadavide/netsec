import java.net.*;
import java.security.*;
import java.io.*;
import javax.net.ssl.*;
import java.nio.charset.StandardCharsets;
public class Client{

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
            SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
            System.out.println(sslContext.getProtocol());
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
            SSLSocketFactory ssf = sslContext.getSocketFactory();
            //SSLSocket ssock = (SSLSocket) ssf.createSocket("192.168.1.112",4433);
            SSLSocket ssock = (SSLSocket) ssf.createSocket(sock,"192.168.1.112", 4433, false);
            for (String s: ssock.getEnabledProtocols()) {           
                //Do your stuff here
                System.out.println(s); 
            }
            System.out.print("Sono qui yeee1\n");
            ssock.startHandshake();
            System.out.print("Sono qui yeee\n");
            pwr.println("EHLO tester.com");
            System.out.println(br.readLine());

            
            

            sock.close();  

        }
        catch (Exception e) {
            e.printStackTrace();
        }
        

        

    }
}
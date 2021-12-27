import java.net.*;
import java.security.*;
import java.io.*;
import javax.net.ssl.*;
import java.util.Base64;
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
            ssock.close();  
            sock.close();

        }
        catch (Exception e) {
            e.printStackTrace();
        }
        

        

    }
}
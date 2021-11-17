import java.io.*;

public class Main {

    public static void main(String[] args) throws IOException {

        /**
         * Authorize by your Maritime Identity Registry instance by using your PKCS12 file (containing the
         * Maritime Connectivity Platform certificate and its associated private key) and obtains a valid token
         */
        String token = TokenUtils.obtainMcpToken("PKCS12/haptikCertificate.p12", "haptik");
        System.out.println(token);
    }
}





import org.apache.commons.io.IOUtils;
import org.apache.http.Header;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.ProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultRedirectStrategy;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.protocol.HttpContext;
import org.apache.http.ssl.SSLContexts;
import org.json.JSONObject;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;


public class TokenUtils extends DefaultRedirectStrategy {
    public static String authenticationCode = "";

    /**
     * Following https://docs.maritimeconnectivity.net/en/latest/MIR.html
     * @return
     * @throws IOException
     */
    public static String obtainMcpToken (String keystorePath, String password) throws IOException {
        try {
            // Adds the PKCS12 KeyStore into the SSLContext and calls the MCCs API to obtain a temporary access_code
            String httpsURL = "https://maritimeid.maritimeconnectivity.net/auth/realms/MCP/protocol/openid-connect/" +
                    "auth?client_id=cert2oidc&redirect_uri=http%3A%2F%2Flocalhost%3A99&response_type=code" +
                    "&kc_idp_hint=certificates&scope=openid";

            try (InputStream keyStoreStream = TokenUtils.class.getResourceAsStream(keystorePath)) {
                KeyStore keyStore = KeyStore.getInstance("PKCS12"); // or JKS
                keyStore.load(keyStoreStream, password.toCharArray());

                SSLContext sslContext = SSLContexts.custom()
                        .loadKeyMaterial(keyStore, password.toCharArray())
                        .build();

                HttpClient httpClient = HttpClients.custom().setSSLContext(sslContext).setRedirectStrategy
                        (new TokenUtils()).build();
                HttpResponse response = httpClient.execute(new HttpGet(httpsURL));
            }

        // by obtaining the temporary authentication code some different redirects are executed
        // the last redirect fails intentional. Therefore, the exception is caught at this point, but not handled.
        } catch (Exception e) { }

        // isolates the temporary access code from the string output from the performed https request
        authenticationCode = authenticationCode.substring(authenticationCode.lastIndexOf("&code=") + 6);

        // Requests MCC endpoint for obtaining a MCC token. The answer is a json object (obj)
        // which contains the MCC access token (mccAccessToken)
        String command = "curl --data \"grant_type=authorization_code&client_id=cert2oidc&code="
                +authenticationCode+"&redirect_uri=http%3A%2F%2Flocalhost%3A99\" " +
                "https://maritimeid.maritimeconnectivity.net/auth/realms/MCP/protocol/openid-connect/token\n";

        Process process = Runtime.getRuntime().exec(command);
        JSONObject obj = new JSONObject(IOUtils.toString(process.getInputStream(), StandardCharsets.UTF_8));
        String mccAccessToken = obj.getString("access_token");
        return mccAccessToken;
    }

    @Override
    public URI getLocationURI(HttpRequest request, HttpResponse response, HttpContext context) throws ProtocolException {
        //get the location header to find out where to redirect to
        final Header locationHeader = response.getFirstHeader("location");
        if (locationHeader == null) {
            // got a redirect response, but no location header
            throw new ProtocolException(
                    "Received redirect response " + response.getStatusLine()
                            + " but no location header");
        }
        TokenUtils.authenticationCode += locationHeader.getValue();
        return super.getLocationURI(request, response, context);
    }
}

package com.microsoft;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.concurrent.Executors;

import com.microsoft.aad.adal4j.AsymmetricKeyCredential;
import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.authentication.KeyVaultCredentials;

public class KeyVaultCertificateAuthenticator {

    /**
     * Do certificate based authentication using pfx file
     * @param path to pfx file
     * @param pfxPassword the password to the pfx file, this can be empty if thats the value given when it was created
     * @param clientId also known as applicationId which is received after app registration
     */
    public static KeyVaultClient getAuthentication(String path, String pfxPassword) throws CertificateException,
            UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, IOException {

    	final String clientId = System.getenv("AZURE_CLIENT_ID");
        final KeyCert certificateKey = readPfx(path,pfxPassword);

        final PrivateKey privateKey = certificateKey.getKey();

        //Do certificate based authentication
        KeyVaultClient keyVaultClient = new KeyVaultClient(new KeyVaultCredentials() {

            @Override
            public String doAuthenticate(String authorization, String resource, String scope) {

                AuthenticationContext context;
                try {
                    context = new AuthenticationContext(authorization, false, Executors.newFixedThreadPool(1));
                    AsymmetricKeyCredential asymmetricKeyCredential = AsymmetricKeyCredential.create(clientId, privateKey, certificateKey.getCertificate());
                    //pass null value for optional callback function and acquire access token
                    AuthenticationResult result = context.acquireToken(resource, asymmetricKeyCredential, null).get();

                    return result.getAccessToken();
                } catch (Exception e) {
                    e.printStackTrace();
                }
                return "";
            }
        });
        return keyVaultClient;
    }

    /**
     * Read pfx file and get privateKey
     * @param path pfx file path
     * @param password the password to the pfx file
     */
    public static KeyCert readPfx(String path, String password) throws NoSuchProviderException, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException {

        try(FileInputStream stream = new FileInputStream(path)){
            final KeyStore store = KeyStore.getInstance("pkcs12", "SunJSSE");
            store.load((InputStream) stream, password.toCharArray());

            KeyCert keyCert = new KeyCert(null,null);

            X509Certificate certificate = null;

            Enumeration<String> aliases = store.aliases();

            while(aliases.hasMoreElements()){
                String alias = aliases.nextElement();
                certificate = (X509Certificate) store.getCertificate(alias);
                System.out.println("the alias is: " + alias);
                PrivateKey key = (PrivateKey)store.getKey(alias,password.toCharArray());
                keyCert.setCertificate(certificate);
                keyCert.setKey(key);

                System.out.println("key in primary encoding format is: " + key.getEncoded());
            }
            return keyCert;
        }
    }

}


class KeyCert {

    X509Certificate certificate;
    PrivateKey key;

    public KeyCert(X509Certificate certificate, PrivateKey key) {
        this.certificate = certificate;
        this.key = key;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    public PrivateKey getKey() {
        return key;
    }

    public void setKey(PrivateKey key) {
        this.key = key;
    }
}
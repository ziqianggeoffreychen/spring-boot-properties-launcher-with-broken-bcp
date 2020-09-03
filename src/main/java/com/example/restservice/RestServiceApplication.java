package com.example.restservice;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.stream.Collectors;

@SpringBootApplication
public class RestServiceApplication {

    private static final Logger logger = LoggerFactory.getLogger(RestServiceApplication.class);

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) {
        SpringApplication.run(RestServiceApplication.class, args).close();

        String rawPemString;

        // Step 1: get X509 certificate
        logger.debug("Start to get certificate");
        rawPemString = getTextFileContent("idp_certificate.cer.pem");
        X509Certificate x509cert = convertCertificate(rawPemString);
        logger.debug("Successfully get certificate");

        // Step 2: get RSA private key
        rawPemString = getTextFileContent("idp_encrypted_private.key.pem");
        logger.info("Try to get private key via PEM:\n\n{}\n", rawPemString);
        PrivateKey privateKey = convertEncryptedPrivateKey(rawPemString, "123456");
        logger.info("Successfully get private key" + privateKey.toString());
        logger.info("Test is done. Now exit.");
    }

    private static String getTextFileContent(String textFilePath) {
        logger.debug("Get content from text file:{}", textFilePath);
        ClassLoader cl = RestServiceApplication.class.getClassLoader();
        InputStream is = cl.getResourceAsStream("classpath:" + textFilePath);
        if (is == null) {
            logger.warn("Fail to locate the resource file from class path. Are you running this app without packaging? Remove prefix and try again.");
            is = cl.getResourceAsStream(textFilePath);
        }
        if (is != null) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(is));
            return (String)reader.lines().collect(Collectors.joining(System.lineSeparator()));
        } else {
            throw new RuntimeException("Resource not found.");
        }
    }

    private static X509Certificate convertCertificate(String pem) {
        logger.debug("enter convertCertificate()");
        try {
            PEMParser pemParser = new PEMParser(new StringReader(pem));
            Object object = pemParser.readObject();
            X509CertificateHolder x509CertificateHolder = (X509CertificateHolder) object;
            JcaX509CertificateConverter converter =
                    new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
            X509Certificate x509Certificate = converter.getCertificate(x509CertificateHolder);
            logger.debug("exit convertCertificate() successfully");
            return x509Certificate;
        } catch (Exception e) {
            String errMsg = "Failed to convert certificate";
            logger.error(errMsg);
            throw new RuntimeException(errMsg, e);
        }
    }

    private static PrivateKey convertEncryptedPrivateKey(String pem, String masterKey) {
        logger.debug("enter convertPrivateKey()");
        try {
            PEMParser pemParser = new PEMParser(new StringReader(pem));
            Object object = pemParser.readObject();
            PEMEncryptedKeyPair ckp = (PEMEncryptedKeyPair) object;
            JcaPEMKeyConverter converter =
                    new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
            PEMDecryptorProvider decProv =
                    new JcePEMDecryptorProviderBuilder().build(masterKey.toCharArray());
            KeyPair kp = converter.getKeyPair(ckp.decryptKeyPair(decProv));
            PrivateKey privateKey = kp.getPrivate();
            logger.debug("exit convertPrivateKey() successfully");
            return privateKey;
        } catch (Exception e) {
            String errMsg = "Failed to convert private key";
            logger.error(errMsg);
            throw new RuntimeException(errMsg, e);
        }
    }
}

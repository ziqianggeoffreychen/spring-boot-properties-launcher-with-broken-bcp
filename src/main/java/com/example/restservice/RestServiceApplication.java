package com.example.restservice;

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
import java.util.stream.Collectors;

@SpringBootApplication
public class RestServiceApplication {

    private static final Logger logger = LoggerFactory.getLogger(RestServiceApplication.class);

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) {
        SpringApplication.run(RestServiceApplication.class, args).close();
        String pem = getTextFileContent("idp_encrypted_private.key.pem");

        logger.info("Try to get private key via PEM:\n\n{}\n", pem);
        PrivateKey privateKey = convertEncryptedPrivateKey(pem, "123456");
        logger.info("Successfully get private key" + privateKey.toString());
        logger.info("Test is done. Now exit.");
    }

    private static String getTextFileContent(String textFilePath) {
        logger.debug("Get content from text file:{}", textFilePath);
        InputStream is = RestServiceApplication.class.getClassLoader().getResourceAsStream("classpath:" + textFilePath);
        if (is != null) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(is));
            return (String)reader.lines().collect(Collectors.joining(System.lineSeparator()));
        } else {
            throw new RuntimeException("Resource not found.");
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

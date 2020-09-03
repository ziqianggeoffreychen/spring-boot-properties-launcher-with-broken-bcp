# spring-boot-properties-launcher-with-broken-bcp
This project is to reproduce the problem reported in https://github.com/spring-projects/spring-boot/issues/23165.

Step 1: Build the Spring Boot fat jar.

```$ mvn clean package```

Step 2: Reproduce the exception:

```$ java -jar target/spring-boot-properties-launcher-with-broken-bcp-0.0.1-SNAPSHOT.jar```

Below log should be outputed:

```
2020-09-03 11:38:30.554 ERROR 22876 --- [           main] c.e.restservice.RestServiceApplication   : Failed to convert private key
Exception in thread "main" java.lang.reflect.InvocationTargetException
        at sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
        at sun.reflect.NativeMethodAccessorImpl.invoke(Unknown Source)
        at sun.reflect.DelegatingMethodAccessorImpl.invoke(Unknown Source)
        at java.lang.reflect.Method.invoke(Unknown Source)
        at org.springframework.boot.loader.MainMethodRunner.run(MainMethodRunner.java:49)
        at org.springframework.boot.loader.Launcher.launch(Launcher.java:109)
        at org.springframework.boot.loader.Launcher.launch(Launcher.java:58)
        at org.springframework.boot.loader.PropertiesLauncher.main(PropertiesLauncher.java:466)
Caused by: java.lang.RuntimeException: Failed to convert private key
        at com.example.restservice.RestServiceApplication.convertEncryptedPrivateKey(RestServiceApplication.java:105)
        at com.example.restservice.RestServiceApplication.main(RestServiceApplication.java:49)
        ... 8 more
Caused by: org.bouncycastle.openssl.PEMException: Unable to create OpenSSL PBDKF: PBKDF-OpenSSL SecretKeyFactory not available
        at org.bouncycastle.openssl.jcajce.PEMUtilities.getKey(Unknown Source)
        at org.bouncycastle.openssl.jcajce.PEMUtilities.getKey(Unknown Source)
        at org.bouncycastle.openssl.jcajce.PEMUtilities.crypt(Unknown Source)
        at org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder$1$1.decrypt(Unknown Source)
        at org.bouncycastle.openssl.PEMEncryptedKeyPair.decryptKeyPair(Unknown Source)
        at com.example.restservice.RestServiceApplication.convertEncryptedPrivateKey(RestServiceApplication.java:98)
        ... 9 more
Caused by: java.security.NoSuchAlgorithmException: PBKDF-OpenSSL SecretKeyFactory not available
        at javax.crypto.SecretKeyFactory.<init>(SecretKeyFactory.java:122)
        at javax.crypto.SecretKeyFactory.getInstance(SecretKeyFactory.java:160)
        at org.bouncycastle.jcajce.util.DefaultJcaJceHelper.createSecretKeyFactory(Unknown Source)
        ... 15 more
```

Step 3: Catch the stack trace (Windows 10 jdb steps is given):

3.1: run app with JDWP enabled.

```$ java -agentlib:jdwp=transport=dt_socket,address=13927,server=y,suspend=y -jar target/spring-boot-properties-launcher-with-broken-bcp-0.0.1-SNAPSHOT.jar```

3.2: connect to JDWP socket and set break point.
```
$ jdb -connect com.sun.jdi.SocketAttach:port=13927
Set uncaught java.lang.Throwable
Set deferred uncaught java.lang.Throwable
Initializing jdb ...
>
VM Started: No frames on the current call stack

main[1] stop at org.springframework.boot.loader.jar.JarFile:365
Deferring breakpoint org.springframework.boot.loader.jar.JarFile:365.
It will be set after the class is loaded.
main[1] cont
> Set deferred breakpoint org.springframework.boot.loader.jar.JarFile:365

Breakpoint hit: "thread=main", org.springframework.boot.loader.jar.JarFile.ensureOpen(), line=365 bci=7

main[1] where
  [1] org.springframework.boot.loader.jar.JarFile.ensureOpen (JarFile.java:365)
  [2] org.springframework.boot.loader.jar.JarFile.getEntry (JarFile.java:266)
  [3] org.springframework.boot.loader.jar.JarFile.getJarEntry (JarFile.java:257)
  [4] org.springframework.boot.loader.jar.JarFile.setupEntryCertificates (JarFile.java:420)
  [5] org.springframework.boot.loader.jar.JarEntry.getCertificates (JarEntry.java:91)
  [6] javax.crypto.JarVerifier.verifySingleJar (JarVerifier.java:497)
  [7] javax.crypto.JarVerifier.verifyJars (JarVerifier.java:363)
  [8] javax.crypto.JarVerifier.verify (JarVerifier.java:289)
  [9] javax.crypto.JceSecurity.verifyProviderJar (JceSecurity.java:164)
  [10] javax.crypto.JceSecurity.getVerificationResult (JceSecurity.java:190)
  [11] javax.crypto.JceSecurity.canUseProvider (JceSecurity.java:204)
  [12] javax.crypto.SecretKeyFactory.nextSpi (SecretKeyFactory.java:295)
  [13] javax.crypto.SecretKeyFactory.<init> (SecretKeyFactory.java:121)
  [14] javax.crypto.SecretKeyFactory.getInstance (SecretKeyFactory.java:160)
  [15] org.bouncycastle.jcajce.util.DefaultJcaJceHelper.createSecretKeyFactory (null)
  [16] org.bouncycastle.openssl.jcajce.PEMUtilities.getKey (null)
  [17] org.bouncycastle.openssl.jcajce.PEMUtilities.getKey (null)
  [18] org.bouncycastle.openssl.jcajce.PEMUtilities.crypt (null)
  [19] org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder$1$1.decrypt (null)
  [20] org.bouncycastle.openssl.PEMEncryptedKeyPair.decryptKeyPair (null)
  [21] com.example.restservice.RestServiceApplication.convertEncryptedPrivateKey (RestServiceApplication.java:105)
  [22] com.example.restservice.RestServiceApplication.main (RestServiceApplication.java:49)
  [23] sun.reflect.NativeMethodAccessorImpl.invoke0 (native method)
  [24] sun.reflect.NativeMethodAccessorImpl.invoke (null)
  [25] sun.reflect.DelegatingMethodAccessorImpl.invoke (null)
  [26] java.lang.reflect.Method.invoke (null)
  [27] org.springframework.boot.loader.MainMethodRunner.run (MainMethodRunner.java:49)
  [28] org.springframework.boot.loader.Launcher.launch (Launcher.java:109)
  [29] org.springframework.boot.loader.Launcher.launch (Launcher.java:58)
  [30] org.springframework.boot.loader.PropertiesLauncher.main (PropertiesLauncher.java:466)
main[1] locals
No local variables
main[1] cont
>
```

Step 4: change to JAR launcher and verify everything is normal.

```
$ sed -i s/ZIP/JAR/ pom.xml
$ mvn clean package && java -jar target/spring-boot-properties-launcher-with-broken-bcp-0.0.1-SNAPSHOT.jar
```

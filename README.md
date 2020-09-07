# Digital-Signing-and-Verifying

# Getting a KeyPair
Make sure that java is installed in your PC. Then execute the below command in the commandline. 
The below command generates private-public key pair. (.p12 file)
```
keytool -genkeypair -alias mykeypair -keyalg RSA -keysize 2048 -dname "CN=Sathish" -validity 365 -storetype PKCS12 -keystore mykeypair.p12 -storepass changeit
```

# Loading the Private Key for Signing
```
			KeyStore keyStore = KeyStore.getInstance("PKCS12");
			keyStore.load(new FileInputStream("D:\\Digital Signature\\mykeypair.p12"), "changeit".toCharArray());
			PrivateKey privateKey = (PrivateKey) keyStore.getKey("senderKeyPair", "changeit".toCharArray());
```

# Publishing the Public Key
```
keytool -exportcert -alias mykeypair -storetype PKCS12 -keystore mykeypair.p12 -file pub_certificate.cer -rfc -storepass changeit
```

# Generate Certificate Signing Request - (Needed for CA signed certificate)
```
keytool -certreq -alias mykeypair -storetype PKCS12 -keystore mykeypair.p12 -file cert_signing_request.csr -storepass changeit
```

# Loading Public Key for Verification

```
  keytool -importcert -alias newkeypair -storetype PKCS12 -keystore newkeypair.p12 -file pub_certificate.cer -storepass changeit
```

```
			import java.security.cert.Certificate;;
			KeyStore keyStore = KeyStore.getInstance("PKCS12");
			keyStore.load(new FileInputStream("newkeypair.p12"), "changeit".toCharArray());
			Certificate certificate = keyStore.getCertificate("newkeypair");
			PublicKey publicKey = certificate.getPublicKey();
```

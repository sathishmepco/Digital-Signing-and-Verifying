# Digital-Signing-and-Verifying

# Key Pair Management
To create a key pair of a private and public key, we'll use the Java keytool.

## Getting a KeyPair
Make sure that java is installed in your PC. Then execute the below command in the commandline. 
The below command generates private-public key pair. (.p12 file)
```
	keytool -genkeypair -alias mykeypair -keyalg RSA -keysize 2048 -dname "CN=Sathish" -validity 365 -storetype PKCS12 -keystore mykeypair.p12 -storepass changeit
```

## Loading the Private Key for Signing
In order to sign a message, we need an instance of the PrivateKey.
```
	KeyStore keyStore = KeyStore.getInstance("PKCS12");
	keyStore.load(new FileInputStream("D:\\Digital Signature\\mykeypair.p12"), "changeit".toCharArray());
	PrivateKey privateKey = (PrivateKey) keyStore.getKey("mykeypair", "changeit".toCharArray());
```

## Publishing the Public Key
In order to verify the signature in other side, we need to have public key.
So along with signature we have to public key to verify the signature of the message.
```
	keytool -exportcert -alias mykeypair -storetype PKCS12 -keystore mykeypair.p12 -file pub_certificate.cer -rfc -storepass changeit
```

## Generate Certificate Signing Request - (Needed for CA signed certificate)
if we're going to work with a CA-signed certificate, then we need to create a certificate signing request (CSR). We do this with the certreq command:
```
	keytool -certreq -alias mykeypair -storetype PKCS12 -keystore mykeypair.p12 -file cert_signing_request.csr -storepass changeit
```

## Loading Public Key for Verification
The receiver can load it into their Keystore using the importcert command
```
	keytool -importcert -alias newkeypair -storetype PKCS12 -keystore newkeypair.p12 -file pub_certificate.cer -storepass changeit
```
We need to have Public Key instance to verify the signature
```
	import java.security.cert.Certificate;;
	KeyStore keyStore = KeyStore.getInstance("PKCS12");
	keyStore.load(new FileInputStream("D:\\Digital Signature\\newkeypair.p12"), "changeit".toCharArray());
	Certificate certificate = keyStore.getCertificate("newkeypair");
	PublicKey publicKey = certificate.getPublicKey();
```

# Digital Signature With MessageDigest and Cipher Classes
## Signing the message (encrypting hash)
```
	byte[] messageBytes = Files.readAllBytes(Paths.get("D:\\Digital Signature\\message.txt"));
	MessageDigest md = MessageDigest.getInstance("SHA-256");
	byte[] messageHash = md.digest(messageBytes);
	Cipher cipher = Cipher.getInstance("RSA");
	cipher.init(Cipher.ENCRYPT_MODE, privateKey);
	byte[] digitalSignature = cipher.doFinal(messageHash);
	Files.write(Paths.get("D:\\Digital Signature\\digital_signature_1"), digitalSignature);
```

## Verifying Signature
```
	byte[] messageBytes = Files.readAllBytes(Paths.get("D:\\Digital Signature\\message.txt"));
	MessageDigest md = MessageDigest.getInstance("SHA-256");
	byte[] messageHash = md.digest(messageBytes);
	byte[] encryptedMessageHash = Files.readAllBytes(Paths.get("D:\\Digital Signature\\digital_signature_1"));
	Cipher cipher = Cipher.getInstance("RSA");
	cipher.init(Cipher.DECRYPT_MODE, publicKey);
	byte[] decryptedMessageHash = cipher.doFinal(encryptedMessageHash);
	boolean isCorrect = Arrays.equals(decryptedMessageHash, messageHash);
	if(isCorrect)
		System.out.println("Verified Successfully.");
	else
		System.out.println("Verification failed!");
```

# Digital Signature Using the Signature Class
## Signing the Message
```
	byte[] messageBytes = Files.readAllBytes(Paths.get("D:\\Digital Signature\\message.txt"));
	MessageDigest md = MessageDigest.getInstance("SHA-256");
	byte[] messageHash = md.digest(messageBytes);
	Signature signature = Signature.getInstance("SHA256withRSA");
	signature.initSign(privateKey);
	signature.update(messageHash);
	byte[] digitalSignature = signature.sign();
	Files.write(Paths.get("D:\\Digital Signature\\digital_signature_2"), digitalSignature);
	System.out.println("Signing is done successfully.");
```

## Verifying the Signature
```
	byte[] messageBytes = Files.readAllBytes(Paths.get("D:\\Digital Signature\\message.txt"));
	MessageDigest md = MessageDigest.getInstance("SHA-256");
	byte[] messageHash = md.digest(messageBytes);
	Signature signature = Signature.getInstance("SHA256withRSA");
	signature.initVerify(publicKey);
	signature.update(messageHash);
	byte[] signatureBytes = Files.readAllBytes(Paths.get("D:\\Digital Signature\\digital_signature_2"));
	boolean isCorrect = signature.verify(signatureBytes);
	if(isCorrect)
		System.out.println("Verified Successfully.");
	else
		System.out.println("Verification failed!");
```
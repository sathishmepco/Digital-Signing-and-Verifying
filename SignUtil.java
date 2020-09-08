import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.cert.Certificate;;

public class SignUtil {
	public SignUtil() {

	}

	private PrivateKey getPrivateKey() {
		try {
			KeyStore keyStore = KeyStore.getInstance("PKCS12");
			keyStore.load(new FileInputStream("D:\\Digital Signature\\mykeypair.p12"), "changeit".toCharArray());
			PrivateKey privateKey = (PrivateKey) keyStore.getKey("mykeypair", "changeit".toCharArray());
			return privateKey;
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public void sign1(){
		PrivateKey privateKey = getPrivateKey();
		if(privateKey == null){
			System.out.println("Private key is not generated.");
			return;
		}
		
		try {
			byte[] messageBytes = Files.readAllBytes(Paths.get("D:\\Digital Signature\\message.txt"));
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] messageHash = md.digest(messageBytes);
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, privateKey);
			byte[] digitalSignature = cipher.doFinal(messageHash);
			Files.write(Paths.get("D:\\Digital Signature\\digital_signature_1"), digitalSignature);
			System.out.println("Signing is done successfully.");
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
	}
	
	public void verify1(){
		PublicKey publicKey = getPublicKey();
		if(publicKey == null){
			System.out.println("Unable to load public key.");
			return;
		}
		try {
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
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
	}

	public PublicKey getPublicKey() {
		try {
			KeyStore keyStore = KeyStore.getInstance("PKCS12");
			keyStore.load(new FileInputStream("D:\\Digital Signature\\newkeypair.p12"), "changeit".toCharArray());
			Certificate certificate = keyStore.getCertificate("newkeypair");
			PublicKey publicKey = certificate.getPublicKey();
			return publicKey;
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public void sign2(){
		PrivateKey privateKey = getPrivateKey();
		if(privateKey == null){
			System.out.println("Private key is not generated.");
			return;
		}
		
		try {
			byte[] messageBytes = Files.readAllBytes(Paths.get("D:\\Digital Signature\\message.txt"));
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] messageHash = md.digest(messageBytes);
			Signature signature = Signature.getInstance("SHA256withRSA");
			signature.initSign(privateKey);
			signature.update(messageHash);
			byte[] digitalSignature = signature.sign();
			Files.write(Paths.get("D:\\Digital Signature\\digital_signature_2"), digitalSignature);
			System.out.println("Signing is done successfully.");
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
	}
	
	public void verify2(){
		PublicKey publicKey = getPublicKey();
		if(publicKey == null){
			System.out.println("Unable to load public key.");
			return;
		}
		
		try {
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
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) {
		SignUtil signUtil = new SignUtil();
		// Approach 1
//		signUtil.sign1();
//		signUtil.verify1();
		
		// Approach 2
		signUtil.sign2();
		signUtil.verify2();
	}
}
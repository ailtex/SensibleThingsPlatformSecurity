package se.sensiblethings.addinlayer.extensions.security.keystore;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.Random;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.bouncycastle.util.encoders.Base64;
import org.junit.Before;
import org.junit.Test;

import se.sensiblethings.addinlayer.extensions.security.certificate.CertificateOperations;
import se.sensiblethings.addinlayer.extensions.security.encryption.AsymmetricEncryption;
import se.sensiblethings.addinlayer.extensions.security.encryption.SymmetricEncryption;

public class KeyStoreJCEKSTest {

	private String keyStoreFile = "resources/KeyStore.db";
	
	private KeyStoreJCEKS keyStore;
	private char[] password = "password".toCharArray();
	
	@Before
	public void setUp() {
		try {
			keyStore = new KeyStoreJCEKS(keyStoreFile, password);
		} catch (IOException e) {
			
			e.printStackTrace();
		}
	}
	
	@Test
	public void testKeyStoreJCEKS() {
	
		File file = new File(keyStoreFile);
		assertTrue("[Test Key StroreJCEKS constructor]", file.exists());
	}


	@Test
	public void testCreateKeyStore() {
		KeyStoreJCEKS keyStore = null;
		try {
			keyStore = new KeyStoreJCEKS(keyStoreFile, password);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		//keyStore.createKeyStore(keyStoreFile, password);
		
		// ???
		assertNotNull("[Test Create KeyStore]", keyStore);
	}
	
	
	@Test
	public void testGetPublicKey() {
		String uci = "Bootstrap-1";
		
		try {	
			KeyPair keyPair = AsymmetricEncryption.generateKey("RSA", 1024);
			
			Certificate cert = CertificateOperations.generateSelfSignedcertificate("CN="+uci, keyPair, 1*365*24*60*60*1000L);
			
			// System.out.println(keyStore.hasCertificate(uci));
			
			// keyStore.storeCertificate(uci, cert, password);
			
			keyStore.storePrivateKey(uci, keyPair.getPrivate(), password, password, new Certificate[]{cert});
			
			// System.out.println(keyStore.hasCertificate(uci));
			// System.out.println(keyStore.hasPrivateKey(uci));
			
			// System.out.println(keyStore.hasCertificate(uci));
			
			// keyStore.storeCertificate(uci, cert, password);
			
			// convert the public key to Hex format, and then compare them
			assertTrue("[Test Get PulicKey]",AsymmetricEncryption.toHexString(keyStore.getPublicKey(uci).getEncoded()).equals(
					AsymmetricEncryption.toHexString(((PublicKey)keyPair.getPublic()).getEncoded())));
			
			// Then Test En/De-cryption with two keys
			String text = "Hello World!";
			
			byte[] cipherTest1 = AsymmetricEncryption.encrypt(keyPair.getPublic(), text.getBytes(), "RSA");
			byte[] plainText1 = AsymmetricEncryption.decrypt((PrivateKey)keyStore.getPrivateKey(uci, password), cipherTest1, "RSA");
			
			assertTrue("[Test Get PulicKey]", text.equals(new String(plainText1)));
			//System.out.println(new String(plainText1));
			
			
			byte[] cipherTest2 = AsymmetricEncryption.encrypt((PublicKey)keyStore.getPublicKey(uci), text.getBytes(), "RSA");
			byte[] plainText2 = AsymmetricEncryption.decrypt(keyPair.getPrivate(), cipherTest1, "RSA");
			
			assertTrue("[Test Get PulicKey]", text.equals(new String(plainText2)));
			//System.out.println(new String(plainText2));
			
		} catch (KeyStoreException | NoSuchAlgorithmException e) {
			
			e.printStackTrace();
		}
		
	}

	@Test
	public void testGetCertificate() {
		String uci = "Bootstrap-2";
		
		try {
			
			KeyPair keyPair = AsymmetricEncryption.generateKey("RSA", 2048);
			Certificate cert = CertificateOperations.generateSelfSignedcertificate("CN="+uci,keyPair, 1*365*24*60*60*1000L);
			keyStore.storeCertificate(uci, cert, password);
			
			assertTrue("[Test Get Certificate]",keyStore.getCertificate(uci).equals(cert));
			assertSame("[Test Get Certificate]",cert, keyStore.getCertificate(uci));
			
		} catch (KeyStoreException | NoSuchAlgorithmException e) {
			
			e.printStackTrace();
		}
	}

	@Test
	public void testGetPrivateKey() {
		String uci = "Bootstrap-3";
		
		try {
			
			KeyPair keyPair = AsymmetricEncryption.generateKey("RSA", 1024);
			Certificate cert = CertificateOperations.generateSelfSignedcertificate("CN="+uci,keyPair, 1*365*24*60*60*1000L);
			
			keyStore.storePrivateKey(uci, keyPair.getPrivate(), password, password, new Certificate[]{cert});
				
			assertEquals("[Test Get Private Key]",keyPair.getPrivate(), keyStore.getPrivateKey(uci, password));
			
			assertEquals("[Test Get Private Key]",AsymmetricEncryption.toHexString(keyPair.getPrivate().getEncoded()), 
					AsymmetricEncryption.toHexString(keyStore.getPrivateKey(uci, password).getEncoded()));
			
			assertTrue(AsymmetricEncryption.toHexString(keyStore.getPrivateKey(uci, password).getEncoded()).equals(
					AsymmetricEncryption.toHexString(keyPair.getPrivate().getEncoded())));
			
		} catch (KeyStoreException | NoSuchAlgorithmException e) {
			
			e.printStackTrace();
		}
	}

	@Test
	public void testGetSecretKey(){
		String uci = "Bootstrap-4";
		
		try {
						
			SecretKey secretKey = SymmetricEncryption.generateKey(SymmetricEncryption.AES, 256);
			keyStore.storeSecretKey(uci, secretKey, password, password);
			
			assertTrue(keyStore.containAlias(uci));
			
			String key1 = Base64.toBase64String(secretKey.getEncoded());
			String key2 = Base64.toBase64String(keyStore.getSecretKey(uci, password).getEncoded());
			assertTrue("[Test Get SecretKey]", key1.equals(key2));
			assertTrue("[Test Get SecretKey]", secretKey.equals(keyStore.getSecretKey(uci, password)));
			
			
			byte[] text = new byte[1024 * 1024];
			new Random().nextBytes(text);
			
			//System.out.println(Base64.toBase64String(text));
			
			byte[] cipherText = null;
			byte[] plainText = null;
			// Test AES ECB MODE with PKCS5 Padding
			long start, end;
			
			start = System.currentTimeMillis();
			cipherText = SymmetricEncryption.encrypt(secretKey, text, SymmetricEncryption.AES_ECB_PKCS5);
			plainText = SymmetricEncryption.decrypt(secretKey, cipherText, SymmetricEncryption.AES_ECB_PKCS5);
			end = System.currentTimeMillis();
			System.out.println("ECB = " + (end - start));
			
			//assertTrue("[Test Get SecretKey]", text.equals(plainText));
			//System.out.println("[" + SymmetricEncryption.AES_ECB_PKCS5 + "] " + Base64.toBase64String(plainText));
			
			
			// Test AES CBC MODE with PKCS5 Padding
			start = System.currentTimeMillis();
			cipherText = SymmetricEncryption.encrypt(secretKey, text, SymmetricEncryption.AES_CBC_PKCS5);
			plainText = SymmetricEncryption.decrypt(secretKey, cipherText, SymmetricEncryption.AES_CBC_PKCS5,
					SymmetricEncryption.getIVparameter());
			
			end = System.currentTimeMillis();
			System.out.println("CBC = " + (end - start));
			
			//assertTrue("[Test Get SecretKey]", text.equals(plainText));
			//System.out.println("[" + SymmetricEncryption.AES_CBC_PKCS5 + "] " + Base64.toBase64String(plainText));
			
			// Test AES CTR Mode with PKCS5 Padding
			start = System.currentTimeMillis();
			cipherText = SymmetricEncryption.encrypt(secretKey, text, "AES/CTR/PKCS5Padding");
			plainText = SymmetricEncryption.decrypt(secretKey, cipherText, "AES/CTR/PKCS5Padding",
					SymmetricEncryption.getIVparameter());
			
			end = System.currentTimeMillis();
			System.out.println("CTR = " + (end - start));
			
			//assertTrue("[Test Get SecretKey]", text.equals(plainText));
			//System.out.println("[AES/CTR/PKCS5Padding] " + Base64.toBase64String(plainText));
			
			// Test AES CFB Mode with PKCS5 Padding
			start = System.currentTimeMillis();
			cipherText = SymmetricEncryption.encrypt(secretKey, text, "AES/CFB/PKCS5Padding");
			plainText = SymmetricEncryption.decrypt(secretKey, cipherText, "AES/CFB/PKCS5Padding",
					SymmetricEncryption.getIVparameter());
			
			end = System.currentTimeMillis();
			System.out.println("CFB = " + (end - start));
			
			//assertTrue("[Test Get SecretKey]", text.equals(plainText));
			//System.out.println("[AES/CFB/PKCS5Padding] " + Base64.toBase64String(plainText));
			
			// Test AES OFB Mode with PKCS5 Padding
			start = System.currentTimeMillis();
			cipherText = SymmetricEncryption.encrypt(secretKey, text, "AES/OFB/PKCS5Padding");
			plainText = SymmetricEncryption.decrypt(secretKey, cipherText, "AES/OFB/PKCS5Padding",
					SymmetricEncryption.getIVparameter());
			
			end = System.currentTimeMillis();
			System.out.println("OFB = " + (end - start));
			
			//assertTrue("[Test Get SecretKey]", text.equals(plainText));
			//System.out.println("[AES/OFB/PKCS5Padding] " + Base64.toBase64String(plainText));
			
			// Test AES PCBC Mode with PKCS5 Padding
			start = System.currentTimeMillis();
			cipherText = SymmetricEncryption.encrypt(secretKey, text, "AES/PCBC/PKCS5Padding");
		    plainText = SymmetricEncryption.decrypt(secretKey, cipherText, "AES/PCBC/PKCS5Padding",
		    		SymmetricEncryption.getIVparameter());
				
		    end = System.currentTimeMillis();
			System.out.println("PCBC = " + (end - start));
			
			//assertTrue("[Test Get SecretKey]", text.equals(plainText));
			//System.out.println("[AES/PCBC/PKCS5Padding] " + Base64.toBase64String(plainText));
			
			
		} catch (KeyStoreException | NoSuchAlgorithmException | 
				InvalidKeyException | InvalidKeySpecException | NoSuchPaddingException | 
				IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
			
			e.printStackTrace();
		}
	}

	@Test
	public void testStorePrivateKey() {
		String uci = "Bootstrap-5";

		KeyPair keyPair;
		try {
			keyPair = AsymmetricEncryption.generateKey("RSA", 2048);
			Certificate cert = CertificateOperations
					.generateSelfSignedcertificate("CN=" + uci, keyPair, 1
							* 365 * 24 * 60 * 60 * 1000L);

			keyStore.storePrivateKey(uci, keyPair.getPrivate(), password,
					password, new Certificate[] { cert });

		} catch (NoSuchAlgorithmException | KeyStoreException e) {
			e.printStackTrace();
		}
		assertTrue("[Test Store Private Key]", keyStore.containAlias(uci));
		//System.out.println(keyStore.toString());	
	}

	@Test
	public void testStoreSecretKeyStringByteArrayCharArray() {
		String uci = "Bootstrap-6";
		SecretKey secretKey;
		try {
			secretKey = SymmetricEncryption.generateKey(SymmetricEncryption.AES, 256);
			keyStore.storeSecretKey(uci, secretKey.getEncoded(), "AES", password, password);
			
		} catch (NoSuchAlgorithmException | InvalidKeyException | KeyStoreException | InvalidKeySpecException e) {
			
			e.printStackTrace();
		}
		assertTrue("[Test Store Private Key by ByteArray]", keyStore.hasKey(uci));
	}

	@Test
	public void testStoreCertificate() {
		String uci = "Bootstrap-7";
		System.out.println(keyStore.toString());
		KeyPair keyPair;
		try {
			keyPair = AsymmetricEncryption.generateKey("RSA", 2048);
			Certificate cert = CertificateOperations
					.generateSelfSignedcertificate("CN=" + uci, keyPair, 1
							* 365 * 24 * 60 * 60 * 1000L);

			keyStore.storeCertificate(uci, cert, password);

		} catch (NoSuchAlgorithmException | KeyStoreException e) {
			e.printStackTrace();
		}
		System.out.println(keyStore.toString());
		assertTrue("[Test Store Certificate]", keyStore.hasCertificate(uci));
	}

	@Test
	public void testHasKey() {
		String uci = "Bootstrap-8";
		SecretKey secretKey;
		try {
			secretKey = SymmetricEncryption.generateKey(SymmetricEncryption.AES, 256);
			keyStore.storeSecretKey(uci, secretKey, password, password);
			
		} catch (NoSuchAlgorithmException | InvalidKeyException | KeyStoreException | InvalidKeySpecException e) {
			
			e.printStackTrace();
		}
		
		assertTrue("[Test has Key]", keyStore.hasKey(uci));
	}

	@Test
	public void testHasCertificate() {
		// same as testStoreCertificate()
	}

	@Test
	public void testContainAlias() {
		String uci = "Bootstrap-x";
		KeyPair keyPair;
		try {
			keyPair = AsymmetricEncryption.generateKey("RSA", 2048);
			Certificate cert = CertificateOperations
					.generateSelfSignedcertificate("CN=" + uci, keyPair, 1
							* 365 * 24 * 60 * 60 * 1000L);

			keyStore.storePrivateKey(uci, keyPair.getPrivate(), password,
					password, new Certificate[] { cert });

		} catch (NoSuchAlgorithmException | KeyStoreException e) {
			e.printStackTrace();
		}
		assertTrue("[Test Store Private Key]", keyStore.containAlias(uci));
	}

	@Test
	public void testGetCreationData() {
		String uci = "Bootstrap-9";
		SecretKey secretKey;
		
		try {
			
			KeyPair keyPair = AsymmetricEncryption.generateKey("RSA", 1024);
			Certificate cert = CertificateOperations.generateSelfSignedcertificate("CN="+uci, keyPair, 1000000);
		
			keyStore.storeCertificate(uci, cert, password);
			System.out.println(keyStore.hasCertificate(uci));
			
			//System.out.println("[Certificate] " + keyStore.getCreationData(uci));
			
			secretKey = SymmetricEncryption.generateKey(SymmetricEncryption.AES, 128);
			
			//System.out.println("[SecreKey] " + keyStore.getCreationData(uci));
			
			// System.out.println(keyStore.hasSecretKey(uci));
			
			keyStore.storeSecretKey(uci, secretKey, password, password);
			
			System.out.println(keyStore.hasCertificate(uci));
			System.out.println(keyStore.hasSecretKey(uci));
			
//			try {
//				Thread.sleep(2000);
//			} catch (InterruptedException e) {
//				// TODO Auto-generated catch block
//				e.printStackTrace();
//			}
			
		} catch (NoSuchAlgorithmException | InvalidKeyException | KeyStoreException | InvalidKeySpecException e) {
			
			e.printStackTrace();
		}
		
		
		//assertTrue("[Test Get Creation Data]", keyStore.getCreationData(uci).after(created));
		
	}

}

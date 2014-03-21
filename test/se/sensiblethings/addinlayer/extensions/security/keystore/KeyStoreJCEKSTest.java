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
import org.junit.Test;

import se.sensiblethings.addinlayer.extensions.security.certificate.CertificateOperations;
import se.sensiblethings.addinlayer.extensions.security.encryption.AsymmetricEncryption;
import se.sensiblethings.addinlayer.extensions.security.encryption.SymmetricEncryption;

public class KeyStoreJCEKSTest {

	private String keyStoreFile = "resouces/KeyStore.db";
	
	@Test
	public void testKeyStoreJCEKS() {
		try {
			KeyStoreJCEKS keyStore = new KeyStoreJCEKS(keyStoreFile,"password".toCharArray());
		} catch (IOException e) {
			e.printStackTrace();
		}
		File file = new File(keyStoreFile);
		assertTrue("[Test Key StroreJCEKS constructor]", file.exists());
	}

	@Test
	public void testLoadKeyStore() {
		KeyStoreJCEKS keyStore = new KeyStoreJCEKS();
		try {
			keyStore.loadKeyStore(keyStoreFile, "password".toCharArray());
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		// ???
		assertNotNull("[Test Load Key Store]", keyStore);
	}

	@Test
	public void testCreateKeyStore() {
		KeyStoreJCEKS keyStore = new KeyStoreJCEKS();
		keyStore.createKeyStore(keyStoreFile, "password".toCharArray());
		
		// ???
		assertNotNull("[Test Create KeyStore]", keyStore);
	}

	@Test
	public void testGetPublicKey() {
		String uci = "Bootstrap-1";
		char[] password = "password".toCharArray();
		
		try {
			KeyStoreJCEKS keyStore = new KeyStoreJCEKS(keyStoreFile, password);
					
			KeyPair keyPair = AsymmetricEncryption.generateKey("RSA", 1024);
			
			Certificate cert = CertificateOperations.generateSelfSignedcertificate("CN="+uci,keyPair, 1*365*24*60*60*1000L);
			keyStore.storePrivateKey(uci, keyPair.getPrivate(), password, password, new Certificate[]{cert});
			
			// It's wired of this test, even convert them to the Hex
			// assertSame("[Test Get PulicKey]",keyStore.getPublicKey(uci).getEncoded(), ((PublicKey)keyPair.getPublic()).getEncoded());
			
			// convert the public key to Hex format, and then compare them
			assertTrue("[Test Get PulicKey]",AsymmetricEncryption.toHexString(keyStore.getPublicKey(uci).getEncoded()).equals(
					AsymmetricEncryption.toHexString(((PublicKey)keyPair.getPublic()).getEncoded())));
			
			// Then Test En/De-cryption with two keys
			String text = "Hello World!";
			
			byte[] cipherTest1 = AsymmetricEncryption.encrypt(keyPair.getPublic(), text.getBytes(), "RSA");
			byte[] plainText1 = AsymmetricEncryption.decrypt((PrivateKey)keyStore.getPrivateKey(uci, password), cipherTest1, "RSA");
			
			assertTrue("[Test Get PulicKey]", text.equals(new String(plainText1)));
			System.out.println(new String(plainText1));
			
			
			byte[] cipherTest2 = AsymmetricEncryption.encrypt((PublicKey)keyStore.getPublicKey(uci), text.getBytes(), "RSA");
			byte[] plainText2 = AsymmetricEncryption.decrypt(keyPair.getPrivate(), cipherTest1, "RSA");
			assertTrue("[Test Get PulicKey]", text.equals(new String(plainText2)));
			System.out.println(new String(plainText2));
			
		} catch (IOException| KeyStoreException | NoSuchAlgorithmException e) {
			
			e.printStackTrace();
		}
		
	}

	@Test
	public void testGetCertificate() {
		String uci = "Bootstrap-2";
		char[] password = "password".toCharArray();
		
		try {
			KeyStoreJCEKS keyStore = new KeyStoreJCEKS(keyStoreFile, password);
			
			KeyPair keyPair = AsymmetricEncryption.generateKey("RSA", 2048);
			Certificate cert = CertificateOperations.generateSelfSignedcertificate("CN="+uci,keyPair, 1*365*24*60*60*1000L);
			keyStore.storeCertificate(uci, cert, password);
			
			assertTrue("[Test Get Certificate]",keyStore.getCertificate(uci).equals(cert));
			assertSame("[Test Get Certificate]",cert, keyStore.getCertificate(uci));
			
		} catch (IOException| KeyStoreException | NoSuchAlgorithmException e) {
			
			e.printStackTrace();
		}
	}

	@Test
	public void testGetPrivateKey() {
		String uci = "Bootstrap-3";
		char[] password = "password".toCharArray();
		
		try {
			KeyStoreJCEKS keyStore = new KeyStoreJCEKS(keyStoreFile, password);
			
			KeyPair keyPair = AsymmetricEncryption.generateKey("RSA", 1024);
			Certificate cert = CertificateOperations.generateSelfSignedcertificate("CN="+uci,keyPair, 1*365*24*60*60*1000L);
			
			keyStore.storePrivateKey(uci, keyPair.getPrivate(), password, password, new Certificate[]{cert});
				
			assertSame("[Test Get Private Key]",keyPair.getPrivate(), keyStore.getPrivateKey(uci, password));
			
			assertSame("[Test Get Private Key]",AsymmetricEncryption.toHexString(keyPair.getPrivate().getEncoded()), 
					AsymmetricEncryption.toHexString(keyStore.getPrivateKey(uci, password).getEncoded()));
			
			assertTrue(AsymmetricEncryption.toHexString(keyStore.getPrivateKey(uci, password).getEncoded()).equals(
					AsymmetricEncryption.toHexString(keyPair.getPrivate().getEncoded())));
			
		} catch (IOException| KeyStoreException | NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Test
	public void testGetSecretKey(){
		String uci = "Bootstrap-4";
		char[] password = "password".toCharArray();
		
		try {
			KeyStoreJCEKS keyStore = new KeyStoreJCEKS(keyStoreFile, password);
						
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
			Date start, end;
			
			start = new Date();
			cipherText = SymmetricEncryption.encrypt(secretKey, text, SymmetricEncryption.AES_ECB_PKCS5);
			plainText = SymmetricEncryption.decrypt(secretKey, cipherText, SymmetricEncryption.AES_ECB_PKCS5);
			end = new Date();
			System.out.println("ECB = " + (end.getTime() - start.getTime()));
			
			//assertTrue("[Test Get SecretKey]", text.equals(plainText));
			//System.out.println("[" + SymmetricEncryption.AES_ECB_PKCS5 + "] " + Base64.toBase64String(plainText));
			
			
			// Test AES CBC MODE with PKCS5 Padding
			start = new Date();
			cipherText = SymmetricEncryption.encrypt(secretKey, text, SymmetricEncryption.AES_CBC_PKCS5);
			plainText = SymmetricEncryption.decrypt(secretKey, cipherText, SymmetricEncryption.AES_CBC_PKCS5,
					SymmetricEncryption.initializationVector);
			
			end = new Date();
			System.out.println("CBC = " + (end.getTime() - start.getTime()));
			
			//assertTrue("[Test Get SecretKey]", text.equals(plainText));
			//System.out.println("[" + SymmetricEncryption.AES_CBC_PKCS5 + "] " + Base64.toBase64String(plainText));
			
			// Test AES CTR Mode with PKCS5 Padding
			start = new Date();
			cipherText = SymmetricEncryption.encrypt(secretKey, text, "AES/CTR/PKCS5Padding");
			plainText = SymmetricEncryption.decrypt(secretKey, cipherText, "AES/CTR/PKCS5Padding",
					SymmetricEncryption.initializationVector);
			
			end = new Date();
			System.out.println("CTR = " + (end.getTime() - start.getTime()));
			
			//assertTrue("[Test Get SecretKey]", text.equals(plainText));
			//System.out.println("[AES/CTR/PKCS5Padding] " + Base64.toBase64String(plainText));
			
			// Test AES CFB Mode with PKCS5 Padding
			start = new Date();
			cipherText = SymmetricEncryption.encrypt(secretKey, text, "AES/CFB/PKCS5Padding");
			plainText = SymmetricEncryption.decrypt(secretKey, cipherText, "AES/CFB/PKCS5Padding",
					SymmetricEncryption.initializationVector);
			
			end = new Date();
			System.out.println("CFB = " + (end.getTime() - start.getTime()));
			
			//assertTrue("[Test Get SecretKey]", text.equals(plainText));
			//System.out.println("[AES/CFB/PKCS5Padding] " + Base64.toBase64String(plainText));
			
			// Test AES OFB Mode with PKCS5 Padding
			start = new Date();
			cipherText = SymmetricEncryption.encrypt(secretKey, text, "AES/OFB/PKCS5Padding");
			plainText = SymmetricEncryption.decrypt(secretKey, cipherText, "AES/OFB/PKCS5Padding",
					SymmetricEncryption.initializationVector);
			
			end = new Date();
			System.out.println("OFB = " + (end.getTime() - start.getTime()));
			
			//assertTrue("[Test Get SecretKey]", text.equals(plainText));
			//System.out.println("[AES/OFB/PKCS5Padding] " + Base64.toBase64String(plainText));
			
			// Test AES PCBC Mode with PKCS5 Padding
			start = new Date();
			cipherText = SymmetricEncryption.encrypt(secretKey, text, "AES/PCBC/PKCS5Padding");
		    plainText = SymmetricEncryption.decrypt(secretKey, cipherText, "AES/PCBC/PKCS5Padding",
			SymmetricEncryption.initializationVector);
				
		    end = new Date();
			System.out.println("PCBC = " + (end.getTime() - start.getTime()));
			
			//assertTrue("[Test Get SecretKey]", text.equals(plainText));
			//System.out.println("[AES/PCBC/PKCS5Padding] " + Base64.toBase64String(plainText));
			
			
		} catch (IOException| KeyStoreException | NoSuchAlgorithmException | 
				InvalidKeyException | InvalidKeySpecException | NoSuchPaddingException | 
				IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
			
			e.printStackTrace();
		}
	}

	@Test
	public void testStorePrivateKey() {
		fail("Not yet implemented");
	}

	@Test
	public void testStoreSecretKeyStringByteArrayCharArray() {
		fail("Not yet implemented");
	}

	@Test
	public void testStoreSecretKeyStringSecretKeyCharArray() {
		fail("Not yet implemented");
	}

	@Test
	public void testStoreCertificate() {
		fail("Not yet implemented");
	}

	@Test
	public void testHasKey() {
		fail("Not yet implemented");
	}

	@Test
	public void testHasCertificate() {
		fail("Not yet implemented");
	}

	@Test
	public void testContainAlias() {
		fail("Not yet implemented");
	}

	@Test
	public void testGetCreationData() {
		fail("Not yet implemented");
	}

}

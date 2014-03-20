package se.sensiblethings.addinlayer.extensions.security.encryption;

import static org.junit.Assert.*;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.Test;

public class AsymmetricEncryptionTest {

	@Test
	public void testGenerateKey() {
		AsymmetricEncryption encrypt = new AsymmetricEncryption();
		
        // Generate keys   
        KeyPair keyPair = null;
		try {
			keyPair = encrypt.generateKey("RSA", 2048);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
        
        assertTrue(keyPair != null);
	}

	@Test
	public void testLoadKeyByteArrayStringString() {
		AsymmetricEncryption encrypt = new AsymmetricEncryption();
		try {
			KeyPair keyPair = AsymmetricEncryption.generateKey("RSA", 1024);
			PublicKey publicKey = (PublicKey)encrypt.loadKey(keyPair.getPublic().getEncoded(), encrypt.publicKey, "RSA");
			PrivateKey privateKey = (PrivateKey)encrypt.loadKey(keyPair.getPrivate().getEncoded(), encrypt.privateKey, "RSA");
			
			assertTrue(publicKey.equals(keyPair.getPublic()));
			assertTrue(privateKey.equals(keyPair.getPrivate()));
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

	@Test
	public void testEncrypt() {
		try {
			String plainText = "Hello World";
			KeyPair keyPair = AsymmetricEncryption.generateKey("RSA", 1024);
			byte[] cipherText = AsymmetricEncryption.encrypt(keyPair.getPublic(), plainText.getBytes(), "RSA");
			
			byte[] text = AsymmetricEncryption.decrypt(keyPair.getPrivate(), cipherText, "RSA");
			assertTrue( new String(text).equals(plainText));
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
	}

	@Test
	public void testDecrypt() {
		// same as testEncrypt except the length of the key
		try {
			String plainText = "Hello World";
			KeyPair keyPair = AsymmetricEncryption.generateKey("RSA", 2048);
			byte[] cipherText = AsymmetricEncryption.encrypt(keyPair.getPublic(), plainText.getBytes(), "RSA");
			
			byte[] text = AsymmetricEncryption.decrypt(keyPair.getPrivate(), cipherText, "RSA");
			assertTrue( new String(text).equals(plainText));
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}


}

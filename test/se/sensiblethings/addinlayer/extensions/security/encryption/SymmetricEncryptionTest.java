package se.sensiblethings.addinlayer.extensions.security.encryption;

import static org.junit.Assert.*;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.junit.Before;
import org.junit.Test;

public class SymmetricEncryptionTest {

	@Before
	public void setUp() throws Exception {
	}

	@Test
	public void testGenerateKey() {
		try {
			SecretKey secretKey = SymmetricEncryption.generateKey("AES", 128);
			assertEquals("[Test Generate Key]","AES",secretKey.getAlgorithm());
			
			secretKey = SymmetricEncryption.generateKey("DES", 56);
			assertEquals("[Test Generate Key]", "DES", secretKey.getAlgorithm());
			
			secretKey = SymmetricEncryption.generateKey("DESede", 168);
			assertEquals("[Test Generate Key]", "DESede", secretKey.getAlgorithm());
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Test
	public void testLoadKey() {
		try {
			SecretKey secretKey = SymmetricEncryption.generateKey("AES", 128);
			SecretKey key = (SecretKey)SymmetricEncryption.loadKey(secretKey.getEncoded(), "AES");
			assertEquals("[Test load Key", secretKey, key);
			
			secretKey = SymmetricEncryption.generateKey("DES", 56);
			key = (SecretKey)SymmetricEncryption.loadKey(secretKey.getEncoded(), "DES");
			assertEquals("[Test load Key", secretKey, key);
			
			secretKey = SymmetricEncryption.generateKey("DESede", 168);
			key = (SecretKey)SymmetricEncryption.loadKey(secretKey.getEncoded(), "DESede");
			assertEquals("[Test load Key", secretKey, key);
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

	@Test
	public void testEncrypt() {
		try {
			SecretKey secretKey = SymmetricEncryption.generateKey("AES", 128);
			byte[] text = "LULU".getBytes();
			byte[] cipherText1 = SymmetricEncryption.encrypt(secretKey, text, SymmetricEncryption.AES_CBC_PKCS5);
			byte[] plainText1 = SymmetricEncryption.decrypt(secretKey, cipherText1, 
					SymmetricEncryption.AES_CBC_PKCS5, SymmetricEncryption.initializationVector);
			
			assertEquals("[Text encrypt]", new String(text), new String(plainText1));
			
			byte[] cipherText2 = SymmetricEncryption.encrypt(secretKey, text, SymmetricEncryption.AES_ECB_PKCS5);
			byte[] plainText2 = SymmetricEncryption.decrypt(secretKey, cipherText2, SymmetricEncryption.AES_ECB_PKCS5);
			assertEquals("[Text encrypt]", new String(text), new String(plainText2));
			
			byte[] cipherText3 = SymmetricEncryption.encrypt(secretKey, text, SymmetricEncryption.AES_CFB_PKCS5);
			byte[] plainText3 = SymmetricEncryption.decrypt(secretKey, cipherText3, 
					SymmetricEncryption.AES_CFB_PKCS5, SymmetricEncryption.initializationVector);
			assertEquals("[Text encrypt]", new String(text), new String(plainText3));
			
			byte[] cipherText4 = SymmetricEncryption.encrypt(secretKey, text, SymmetricEncryption.AES_OFB_PKCS5);
			byte[] plainText4 = SymmetricEncryption.decrypt(secretKey, cipherText4, 
					SymmetricEncryption.AES_OFB_PKCS5, SymmetricEncryption.initializationVector);
			assertEquals("[Text encrypt]", new String(text), new String(plainText4));
			
			byte[] cipherText5 = SymmetricEncryption.encrypt(secretKey, text, SymmetricEncryption.AES_CTR_PKCS5);
			byte[] plainText5 = SymmetricEncryption.decrypt(secretKey, cipherText5, 
					SymmetricEncryption.AES_CTR_PKCS5, SymmetricEncryption.initializationVector);
			assertEquals("[Text encrypt]", new String(text), new String(plainText5));
			
			byte[] cipherText6 = SymmetricEncryption.encrypt(secretKey, text, SymmetricEncryption.AES_PCBC_PKCS5);
			byte[] plainText6 = SymmetricEncryption.decrypt(secretKey, cipherText6, 
					SymmetricEncryption.AES_PCBC_PKCS5, SymmetricEncryption.initializationVector);
			assertEquals("[Text encrypt]", new String(text), new String(plainText6));
			
		} catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException |
				IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

	@Test
	public void testDecryptSecretKeyByteArrayString() {
		// same as encrypt test
	}


}

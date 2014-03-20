package se.sensiblethings.addinlayer.extensions.security.encryption;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class SymmetricEncryption {
	// These are encryption algorithms
	public static final String AES = "AES";
	public static final String DES = "DES";
	public static final String DESede = "DESede";
	
	// These are  encryption modes with different same padding
	public static final String DES_ECB_PKCS5 = "DES/ECB/PKCS5Padding";
	public static final String DES_CBC_PKCS5 = "DES/CBC/PKCS5Padding";
	public static final String DESede_CBC_PKCS5 = "DESede/CBC/PKCS5Padding";
	public static final String DESede_ECB_PKCS5 = "DESede/ECB/PKCS5Padding";
	public static final String AES_CBC_PKCS5 = "AES/CBC/PKCS5Padding";
	public static final String AES_ECB_PKCS5 = "AES/ECB/PKCS5Padding";
	
	
	public static SecretKey generateKey(String algorithm, int keyLength) throws NoSuchAlgorithmException{
		KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
		
		keyGenerator.init(keyLength, new SecureRandom());
		return keyGenerator.generateKey();
	}
	
	public static Key loadKey(byte[] key, String algorithm){
		
		SecretKey secretKey = new SecretKeySpec(key, algorithm);
	    return secretKey;
	}
	
	public static byte[] encrypt(SecretKey key, byte[] data, String mode) throws 
	NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		
		Cipher cipher = Cipher.getInstance(mode);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(data);
	}
	
	public static byte[] decrypt(SecretKey key, byte[] data, String mode) throws 
	NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		
		Cipher cipher = Cipher.getInstance(mode);
		cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(data);
	}
}

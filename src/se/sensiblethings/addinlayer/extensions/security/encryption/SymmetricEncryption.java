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

public class SymmetricEncryption {
	
	public static final String AES = "AES";
	public static final String DES = "DES";
	public static final String DESede = "DESede";
	
	public static final String DES_ECB_PKCS5 = "DES/ECB/PKCS5Padding";
	public static final String DES_CBC_PKCS5 = "DES/CBC/PKCS5Padding";
	public static final String DESede_CBC_PKCS5 = "DESede/CBC/PKCS5Padding";
	public static final String DESede_ECB_PKCS5 = "DESede/ECB/PKCS5Padding";
	public static final String AES_CBC_PKCS5 = "AES/CBC/PKCS5Padding";
	public static final String AES_ECB_PKCS5 = "AES/ECB/PKCS5Padding";
	
	private static final Map<String, Integer> keySizeMap;
	static {
		keySizeMap = new HashMap<String,Integer>();
		
		keySizeMap.put("DES", 56);
		keySizeMap.put("DESede", 168);
		keySizeMap.put("AES", 128);
	}
	
	
	public static SecretKey generateKey(String algorithm) throws NoSuchAlgorithmException{
		KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
		
		keyGenerator.init(keySizeMap.get(algorithm), new SecureRandom());
		return keyGenerator.generateKey();
	}
	
	public Key loadKey(byte[] key, String algorithm) throws 
	InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
		
		DESKeySpec des = new DESKeySpec(key);  
	    SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(algorithm);  
	    SecretKey secretKey = keyFactory.generateSecret(des);  
	    return secretKey;
	}
	
	public static byte[] encrypt(SecretKey key, byte[] data) throws 
	NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		
		Cipher cipher = Cipher.getInstance(AES_CBC_PKCS5);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(data);
	}
	
	public static byte[] decrypt(SecretKey key, byte[] data) throws 
	NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		
		Cipher cipher = Cipher.getInstance(AES_CBC_PKCS5);
		cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(data);
	}
}

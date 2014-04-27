package se.sensiblethings.addinlayer.extensions.security.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.bouncycastle.util.encoders.Base64;

import se.sensiblethings.addinlayer.extensions.security.encryption.SymmetricEncryption;

public class SymmetricEncryptionPerformanceTest {
	public static final String algorithm = SymmetricEncryption.AES;
	public static final String mode = SymmetricEncryption.AES_ECB_PKCS5;
	public static final int length = 128;
	
	public static final int messageLength = 100000;
	public static final int messageCnt = 10000;
	
	private SecretKey secretKey = null;
	
	public static void main(String[] agrs){
		SymmetricEncryptionPerformanceTest test = new SymmetricEncryptionPerformanceTest();
		test.run();
	}
	
	public SymmetricEncryptionPerformanceTest(){
		try {
			secretKey = SymmetricEncryption.generateKey(algorithm, length);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
	
	public void run(){
		
		long totalTime = 0;
		try {
			
			for(int i = 0; i < messageCnt; i++){
				byte[] text = generateMessage(messageLength);
				
				long start = System.nanoTime();
				
				byte[]  cipherText = SymmetricEncryption.encrypt(secretKey, text, mode);
//				byte[] plainText = SymmetricEncryption.decrypt(secretKey, cipherText, mode);
				
				byte[] plainText = SymmetricEncryption.decrypt(secretKey, cipherText, mode);
				
				long end = System.nanoTime();
				
				if(!Base64.toBase64String(plainText).equals(Base64.toBase64String(text))){
					System.err.println("En/Decrypt Error !");
				}
				System.out.println("[ The "+ i + " packet] time takes :" + (end-start));
				totalTime += end - start;
			}
			
			System.out.println("[ Total Time ] : " + totalTime);
			
		} catch (InvalidKeyException | NoSuchAlgorithmException
				| NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException | InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
		
		
	}
	
	private byte[] generateMessage(int length) {
		Random random = new Random(System.currentTimeMillis());
		byte[] message = new byte[length];
		random.nextBytes(message);
		
		return message;
	}
}

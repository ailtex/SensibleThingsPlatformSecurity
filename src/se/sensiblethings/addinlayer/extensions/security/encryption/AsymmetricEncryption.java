package se.sensiblethings.addinlayer.extensions.security.encryption;

import java.security.Key;   
import java.security.KeyFactory;   
import java.security.KeyPair;   
import java.security.KeyPairGenerator;   
import java.security.NoSuchAlgorithmException;   
import java.security.PrivateKey;   
import java.security.PublicKey;   
import java.security.SecureRandom;   
import java.security.interfaces.RSAPrivateKey;   
import java.security.interfaces.RSAPublicKey;   
import java.security.spec.InvalidKeySpecException;   
import java.security.spec.PKCS8EncodedKeySpec;   
import java.security.spec.X509EncodedKeySpec;   
import javax.crypto.Cipher;   


import org.apache.commons.configuration.ConfigurationException;   
import org.apache.commons.configuration.PropertiesConfiguration;   
import org.bouncycastle.jce.provider.BouncyCastleProvider;   

public class AsymmetricEncryption {
	
	public static final String publicKey = "PUBLIC";
	public static final String privateKey = "PRIVATE";
	
	public static final String RSA = "RSA"; // Recommended length 2028
	
	public static KeyPair generateKey(String algorithm, int keyLength) throws NoSuchAlgorithmException {   
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(algorithm);   
        keyPairGen.initialize(keyLength, new SecureRandom());   
  
        return keyPairGen.generateKeyPair();
    }   
	
	public Key loadKey(byte[] key, String type, String algorithm){   
   	 
        KeyFactory keyFactory;
		try {
			keyFactory = KeyFactory.getInstance(algorithm);
		 
	        if (type.equals(privateKey)) {    
	            PKCS8EncodedKeySpec priPKCS8 = new PKCS8EncodedKeySpec(key);   
	            PrivateKey privateKey = keyFactory.generatePrivate(priPKCS8);
	            
	            return privateKey;   
	  
	        } else if(type.equals(publicKey)){    
	            X509EncodedKeySpec bobPubKeySpec = new X509EncodedKeySpec(key);   
	            PublicKey publicKey = keyFactory.generatePublic(bobPubKeySpec);
	            
	            return publicKey;   
	        }
	        
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}   
        return null;
    }  
	
	/**
     * 
     * @param publicKey
     * @param data
     * @return
     */
    public static byte[] encrypt(RSAPublicKey publicKey, byte[] data, String algorithm) {   
        if (publicKey != null) {   
            try {   
                Cipher cipher = Cipher.getInstance(algorithm);
                
                cipher.init(Cipher.ENCRYPT_MODE, publicKey);
                
                return cipher.doFinal(data);   
            } catch (Exception e) {   
                e.printStackTrace();   
            }   
        }   
        return null;   
    }   
    

    public static byte[] decrypt(RSAPrivateKey privateKey, byte[] raw, String algorithm) {   
        if (privateKey != null) {   
            try {   
            	Cipher cipher = Cipher.getInstance(algorithm);
                cipher.init(Cipher.DECRYPT_MODE, privateKey);   
                return cipher.doFinal(raw);   
            } catch (Exception e) {   
                e.printStackTrace();   
            }   
        }   
  
        return null;   
    }
	
    
    /**  
     * sign a message.  
     *   
     * @return byte[]  
     */  
    public byte[] sign(RSAPrivateKey privateKey, byte[] data, String algorithm) {   
        if (privateKey != null) {   
            try {   
                Cipher cipher = Cipher.getInstance(algorithm);
                
                cipher.init(Cipher.ENCRYPT_MODE, privateKey);
                
                return cipher.doFinal(data);   
            } catch (Exception e) {   
                e.printStackTrace();   
            }   
        }   
        return null;   
    } 
    
    public void saveKey(KeyPair keyPair, String publicKeyFile,   
            String privateKeyFile) throws ConfigurationException {   
        PublicKey pubkey = keyPair.getPublic();   
        PrivateKey prikey = keyPair.getPrivate();   
  
        // save public key   
        PropertiesConfiguration publicConfig = new PropertiesConfiguration(   
                publicKeyFile);   
        publicConfig.setProperty("PULIICKEY", toHexString(pubkey.getEncoded())); 
        publicConfig.save();   
  
        // save private key   
        PropertiesConfiguration privateConfig = new PropertiesConfiguration(   
                privateKeyFile);   
        privateConfig.setProperty("PRIVATEKEY",   
                toHexString(prikey.getEncoded()));   
        privateConfig.save();   
    }   
    
    
    
    /**  
     * @param filename  
     * @param type  
     *            1-public 0-private  
     * @return  
     * @throws ConfigurationException  
     * @throws NoSuchAlgorithmException  
     * @throws InvalidKeySpecException  
     */  
    public Key loadKey(String filename, int type)   
            throws ConfigurationException, NoSuchAlgorithmException,   
            InvalidKeySpecException {   
        PropertiesConfiguration config = new PropertiesConfiguration(filename);   
        KeyFactory keyFactory = KeyFactory.getInstance("RSA",   
                new BouncyCastleProvider());   
  
        if (type == 0) {   
            // privateKey   
            String privateKeyValue = config.getString("PULIICKEY");   
            PKCS8EncodedKeySpec priPKCS8 = new PKCS8EncodedKeySpec(   
                    toBytes(privateKeyValue));   
            PrivateKey privateKey = keyFactory.generatePrivate(priPKCS8);   
            return privateKey;   
  
        } else {   
            // publicKey   
            String privateKeyValue = config.getString("PRIVATEKEY");   
            X509EncodedKeySpec bobPubKeySpec = new X509EncodedKeySpec(   
                    toBytes(privateKeyValue));   
            PublicKey publicKey = keyFactory.generatePublic(bobPubKeySpec);   
            return publicKey;   
        }   
    }   
    
  

    
    public static String toHexString(byte[] b) {   
        StringBuilder sb = new StringBuilder(b.length * 2);   
        for (int i = 0; i < b.length; i++) {   
            sb.append(HEXCHAR[(b[i] & 0xf0) >>> 4]);   
            sb.append(HEXCHAR[b[i] & 0x0f]);   
        }   
        return sb.toString();   
    }   
  
    public static final byte[] toBytes(String s) {   
        byte[] bytes;   
        bytes = new byte[s.length() / 2];   
        for (int i = 0; i < bytes.length; i++) {   
            bytes[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2),   
                    16);   
        }   
        return bytes;   
    }   
  
    private static char[] HEXCHAR = { '0', '1', '2', '3', '4', '5', '6', '7',   
            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };  
    
    
    public static void main(String[] agrs){
		try {   
            AsymmetricEncryption encrypt = new AsymmetricEncryption();   
            String encryptText = "Hello";   
  
            // Generate keys   
            KeyPair keyPair = encrypt.generateKey(encrypt.RSA, 2048);   
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();   
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();   
            
            //System.out.println(privateKey.toString());
            //System.out.println(publicKey.toString());
            
            encrypt.saveKey(keyPair, "publicKey","privateKey");
            
            byte[] e = encrypt.encrypt(publicKey, encryptText.getBytes(), encrypt.RSA); 
            System.out.println(toHexString(encryptText.getBytes()));
            byte[] de = encrypt.decrypt(privateKey, e, encrypt.RSA);   
            System.out.println(toHexString(e));   
            System.out.println(toHexString(de));   
        } catch (Exception e) {   
            e.printStackTrace();   
        }   
	}
}

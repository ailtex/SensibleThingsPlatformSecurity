package se.sensiblethings.addinlayer.extensions.security.keystore;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStore.TrustedCertificateEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;

import javax.crypto.SecretKey;

import se.sensiblethings.addinlayer.extensions.security.encryption.AsymmetricEncryption;
import se.sensiblethings.addinlayer.extensions.security.encryption.SymmetricEncryption;

public class KeyStoreJCA implements KeyStoreTemplate{
	
	private KeyStore ks = null;
	private String keyStoreFile = null;
	
	public void keyStoreJCA(){
		
		// "KeyStore" the file name, which stores the keys
		// "password" the password of the keystore
		// createKeyStore("KeyStore", "password".toCharArray());
	}
	
	public void loadKeyStore(String keyStoreFile, char[] password) throws  IOException {
		
		FileInputStream fis = null;
		
		try {
			ks = KeyStore.getInstance(KeyStore.getDefaultType());
			fis = new FileInputStream(keyStoreFile);
			
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch(FileNotFoundException e){
			e.printStackTrace();
			
			// if this file not found, it should create a new one
			// then load the new one
			createKeyStore(keyStoreFile, password);
			fis = new FileInputStream(keyStoreFile);
		} 
		
		
		try {
			ks.load(fis, password);
		} catch (NoSuchAlgorithmException | CertificateException e) {
			
			e.printStackTrace();
		}
		
		this.keyStoreFile = keyStoreFile;
		
		if(fis != null) fis.close();
	}
	
	private boolean updataKeyStore(char[] password){
		
		FileOutputStream fos = null;
		try {
			fos = new FileOutputStream(keyStoreFile);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			return false;
		}
		
		try {
			ks.store(fos, password);
			
			if(fos != null) fos.close();
		} catch (KeyStoreException | NoSuchAlgorithmException
				| CertificateException | IOException e) {
			e.printStackTrace();
			return false;
		}
		
		return true;
	}
	
	
	public void createKeyStore(String KeyStoreFile, char[] password){
		// There is a built-in default keystore implementation type known as
		// "jks" that is provided by Sun Microsystems.
		// It implements the keystore as a file, utilizing a proprietary
		// keystore type (format).
		// It protects each private key with its own individual password,
		// and also protects the integrity of the entire keystore with a
		// (possibly different) password.
		//
		// "jceks" is an alternate proprietary keystore format to "jks" that
		// uses much stronger encryption in the form of Password-Based
		// Encryption with Triple-DES.
		//
		// Keystore type designations are not case-sensitive.
		KeyStore ks = null;
		
		try {
			ks = KeyStore.getInstance(KeyStore.getDefaultType());
			
			// set the password
			ks.load(null, password);
			
			// Store away the keystore.
			FileOutputStream fos = new FileOutputStream(KeyStoreFile);
			ks.store(fos, password);
			if(fos != null){
				fos.close();
			}
		} catch (KeyStoreException| NoSuchAlgorithmException | CertificateException | IOException e) {
			
			e.printStackTrace();
		}
		
	}
	
	public Key getPublicKey(String alias){
		
		Key key = null;
		try {
			key = ks.getCertificate(alias).getPublicKey();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		
		return key;
	}
	
	public Certificate getCertificate(String alias) throws KeyStoreException{
		return ks.getCertificate(alias);
	}
	
	
	public Key getPrivateKey(String alias, char[] password) {
		
		Key key = null;
		try {
			PrivateKeyEntry pkEntry = (PrivateKeyEntry) ks.getEntry(alias,  new PasswordProtection(password));
			key = pkEntry.getPrivateKey();
		} catch (NoSuchAlgorithmException | UnrecoverableEntryException
				| KeyStoreException e) {
			e.printStackTrace();
		}
		return key;
	}
	
	
	public Key getSecretKey(String alias, char[] password){
		Key key = null;
		try {
			SecretKeyEntry pkEntry = (SecretKeyEntry) ks.getEntry(alias,  new PasswordProtection(password));
			key = pkEntry.getSecretKey();
			
		} catch (NoSuchAlgorithmException | UnrecoverableEntryException
				| KeyStoreException e) {
			e.printStackTrace();
		}
		return key;
	}
	

	/**
	 * 
	 * @param alias
	 * @param privateKey
	 * @param password
	 * @param cert the self signed X509 v1 certificate
	 * @return
	 * @throws KeyStoreException
	 */
	public boolean storePrivateKey(String alias, 
			PrivateKey privateKey, 
			char[] password, 
			Certificate[] certs) throws KeyStoreException{

		// the certificate chain is required to store the private key
		// Generate the certificate chain
		// password same as the keystore
		ks.setKeyEntry(alias, privateKey, password, certs);
		
		// keystore password needed
		return updataKeyStore(password);
		
	}
	
	public boolean storeSecretKey(String alias, byte[] secretKey, char[] password) throws 
	KeyStoreException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException{
		
		// firstly transform the secretKey
		SymmetricEncryption aes = new SymmetricEncryption();
		SecretKey sk = (SecretKey)aes.loadKey(secretKey, aes.AES);
		
		SecretKeyEntry skEntry = new SecretKeyEntry(sk);
		
		ks.setEntry(alias, skEntry, new PasswordProtection(password));
	
		// password needed
		
		return updataKeyStore("password".toCharArray());
		
	}
	
	public boolean storeSecretKey(String alias, SecretKey secretKey, char[] password) throws 
	KeyStoreException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException{
		
		SecretKeyEntry skEntry = new SecretKeyEntry(secretKey);
		
		// ProtectionParameter implemented by PasswordProtection
		ks.setEntry(alias, skEntry, new PasswordProtection(password));
		
		// password needed
		return updataKeyStore("password".toCharArray());
		
	}
	
	public boolean storeCertificate(String alias, Certificate certificate, char[] password) throws KeyStoreException{
		
		TrustedCertificateEntry cerEntry = new TrustedCertificateEntry(certificate);
		ks.setCertificateEntry(alias, certificate);
		
		// password needed
		return updataKeyStore(password);
		
	}
	
	
	public boolean hasKey(String alias){
		try {
			return ks.isKeyEntry(alias);
		} catch (KeyStoreException e) {
			
			e.printStackTrace();
		}
		
		return false;
	}
	
	public boolean hasCertificate(String alias){
		try {
			return ks.isCertificateEntry(alias);
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		
		return false;
	}
	
	public Date getCreationData(String alias){
		
		try {
			return ks.getCreationDate(alias);
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return null;
	}
}

package se.sensiblethings.addinlayer.extensions.security.keystore;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
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

import se.sensiblethings.addinlayer.extensions.security.encryption.RSAEncryption;
import se.sensiblethings.addinlayer.extensions.security.encryption.SymmetricEncryption;

public class KeyStoreJCA implements KeyStoreTemplate{
	
	private KeyStore ks = null;
	private String keyStoreFile = null;
	
	public void keyStoreJCA(){
		
		// "KeyStore" the file name, which stores the keys
		// "password" the password of the keystore
		createKeyStore("KeyStore", "password".toCharArray());
	}
	
	public void loadKeyStore(String keyStoreFile, char[] password) throws 
	NoSuchAlgorithmException, CertificateException, IOException {
		
		try {
			ks = KeyStore.getInstance(KeyStore.getDefaultType());
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		
		FileInputStream fis = new FileInputStream(keyStoreFile);
		this.keyStoreFile = keyStoreFile;
		
		ks.load(fis, password);
		
		if(fis != null) fis.close();
	}
	
	private void updataKeyStore(char[] password) throws 
	KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException{
		
		FileOutputStream fos = null;
		try {
			fos = new FileOutputStream(keyStoreFile);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		
		ks.store(fos, password);
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
	
	@Override
	public boolean getConnection(String databaseURL) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean configureAndInitialize() {
		// TODO Auto-generated method stub
		return false;
	}
	
	@Override
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
	
	@Override
	public Key getPrivateKey(String alias) {
		
		Key key = null;
		try {
			PrivateKeyEntry pkEntry = (PrivateKeyEntry) ks.getEntry(alias, null);
			key = pkEntry.getPrivateKey();
		} catch (NoSuchAlgorithmException | UnrecoverableEntryException
				| KeyStoreException e) {
			e.printStackTrace();
		}
		return key;
	}
	
	
	public Key getSecretKey(String alias){
		Key key = null;
		try {
			SecretKeyEntry pkEntry = (SecretKeyEntry) ks.getEntry(alias, null);
			key = pkEntry.getSecretKey();
			
		} catch (NoSuchAlgorithmException | UnrecoverableEntryException
				| KeyStoreException e) {
			e.printStackTrace();
		}
		return key;
	}
	
	@Override
	public boolean storePublicKey(String alias, byte[] publicKey) {
		// TODO Auto-generated method stub
		return false;
	}
	
	
	public boolean storePrivateKey(String alias, byte[] privateKey, char[] password, Certificate[] certChain) throws KeyStoreException{
		// firstly transform the PrivateKey
		RSAEncryption rsa = new RSAEncryption();
		PrivateKey pk = (PrivateKey)rsa.loadKey(privateKey, rsa.privateKey);
		
		// certificate chain : null
		PrivateKeyEntry pkEntry = new PrivateKeyEntry(pk, null);
		
		// certificate chain is null, it may get exception
		// Generate the certificate chain
		// X509Certificate certificate = call CertificateOperations.generateSelfSignedCertificate(); 
		
		ks.setKeyEntry(alias, pk, password, certChain);
		
		// password needed
		try {
			updataKeyStore("password".toCharArray());
		} catch (NoSuchAlgorithmException | CertificateException | IOException e) {
			e.printStackTrace();
		}
		
		return true;
	}
	
	public boolean storeSecretKey(String alias, byte[] secretKey, char[] password) throws 
	KeyStoreException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException{
		// firstly transform the secretKey
		SymmetricEncryption aes = new SymmetricEncryption();
		SecretKey sk = (SecretKey)aes.loadKey(secretKey, aes.AES);
		
		SecretKeyEntry skEntry = new SecretKeyEntry(sk);
		// ProtectionParameter : null
		ks.setEntry(alias, skEntry, null);
	
		// password needed
		try {
			updataKeyStore("password".toCharArray());
		} catch (NoSuchAlgorithmException | CertificateException | IOException e) {
			e.printStackTrace();
		}
		return true;
	}
	
	
	
	public boolean storeCertification(String alias, Certificate certificate) throws KeyStoreException{
		
		TrustedCertificateEntry cerEntry = new TrustedCertificateEntry(certificate);
		ks.setCertificateEntry(alias, certificate);
		
		// password needed
		try {
			updataKeyStore("password".toCharArray());
		} catch (NoSuchAlgorithmException | CertificateException | IOException e) {
			e.printStackTrace();
		}
		
		return true;
	}
	
	@Override
	public boolean storeCertification(String alias, byte[] publicKey,
			String certification, Date validation) {
		
		return false;
	}

	@Override
	public boolean closeDatabase() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean hasKeyPair(String alias) {
		// TODO Auto-generated method stub
		return false;
	}

}

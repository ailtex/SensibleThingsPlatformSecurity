package se.sensiblethings.addinlayer.extensions.security;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;

import se.sensiblethings.addinlayer.extensions.security.certificate.CertificateOperations;
import se.sensiblethings.addinlayer.extensions.security.encryption.AsymmetricEncryption;
import se.sensiblethings.addinlayer.extensions.security.keystore.KeyStoreJCA;
import se.sensiblethings.addinlayer.extensions.security.keystore.KeyStoreTemplate;
import se.sensiblethings.addinlayer.extensions.security.keystore.SQLiteDatabase;
import se.sensiblethings.addinlayer.extensions.security.messagedigest.MessageDigestOperations;
import se.sensiblethings.addinlayer.extensions.security.signature.SignatureOperations;
import se.sensiblethings.addinlayer.extensions.security.encryption.SymmetricEncryption;

public class SecurityManager {
	
	// the operator is the uci who owns
	private String operator = null;
	private PublicKey publicKey = null;
	private String registrationRequestTime = null;
	private String bootStrapUci = null;
	
	KeyStoreJCA keyStore = null;
	
	public SecurityManager(){
		/*
		keyStore = new SQLiteDatabase();
		// firstly connect to permanent key store
		keyStore.getConnection(SQLiteDatabase.PKS_keystore_URL);
		//initial the database
		keyStore.configureAndInitialize();
		*/
		keyStore = new KeyStoreJCA();
		
		try {
			keyStore.loadKeyStore("KeyStore", "password".toCharArray());
		} catch ( IOException e) {
			// it may fail to load the key store
			e.printStackTrace();
		}
		
	}
	
	public void initializePermanentKeyStore(String uci){
		setOperator(uci);
		
		// check weather the store has the KeyPair
		if(!keyStore.hasKeyPair(uci)){
			// if not, create the key pair
			CreateKeyPairAndCertificate(uci);
		}
		
	}
	
	protected void CreateKeyPairAndCertificate(String uci){
		// sun.security.X509 package provides many APIs to use
		// e.g. CertAndKeyGen gen = new CertAndKeyGen(keyAlgName, sigAlgName, providerName);
		// it can generate the RSA keypair and self signed certificate
		// While it is not recommended to use sun.* packages
		// Reason to see : http://www.oracle.com/technetwork/java/faq-sun-packages-142232.html
		KeyPair keyPair = null;
		try {
			 keyPair = AsymmetricEncryption.generateKey(AsymmetricEncryption.RSA, 2048);
		} catch (NoSuchAlgorithmException e) {
			
			e.printStackTrace();
		}
		
		// generate the self signed X509 v1 certificate
		CertificateOperations certOpert = new CertificateOperations();
		
		// setting the subject name of the certificate
		String subjectName = "CN=" + uci + ",OU=ComputerColleage,O=MIUN,C=Sweden";
		Certificate cert = certOpert.generateSelfSignedcertificate(subjectName, keyPair);
		
		try {
			// store the private key with the self signed certificate
			keyStore.storePrivateKey(uci, keyPair.getPrivate(), "password".toCharArray(), cert);
			
			// store the self signed certificate
			keyStore.storeCertification(uci, cert, "password".toCharArray());
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
	}
	
	
	public String signMessage(String message, String algorithm){
		// load the private key
		PrivateKey privateKey = (PrivateKey) keyStore.getPrivateKey(operator);
		
		String signature = null;
		try {
			signature = new String(SignatureOperations.sign(message.getBytes(), privateKey, algorithm));
		} catch (InvalidKeyException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		return signature;
	}
	
	public boolean verifySignature(String message, String signature, PublicKey publicKey, String algorithm){
		try {
			return SignatureOperations.verify(message.getBytes(), signature.getBytes(), publicKey, algorithm);
		} catch (InvalidKeyException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return false;
	}
	
	public boolean verifyRequest(String signature, String publicKey){
		/*
		AsymmetricEncryption rsa = new AsymmetricEncryption();
		RSAPrivateKey key = (RSAPrivateKey)rsa.loadKey(publicKey.getBytes(), rsa.publicKey);
		
		String[] signaturePlainText = new String(rsa.decrypt(key, signature.getBytes())).split(",");
		if(signaturePlainText[0].equals(bootStrapUci) && signaturePlainText[1].equals(registrationRequestTime)){
			return true;
		}else{
			return false;
		}
		*/
		return false;
	}
	
	/**
	 * Encrypt message with RSA encryption
	 * @param message
	 * @param algorithm
	 * @return
	 */
	public String encryptMessage(String sendToUci, String message, String algorithm){
		
		PublicKey publicKey = (PublicKey)keyStore.getPublicKey(sendToUci);
		
		String encryptedMessage = new String (AsymmetricEncryption.encrypt(publicKey, message.getBytes(), algorithm));
		
		return encryptedMessage;
	}
	
	/**
	 * Decrypt message with RSA encryption
	 * @param message
	 * @return
	 */
	public String decryptMessage(String message, String algorithm){
		// load the private key
		PrivateKey privateKey = (PrivateKey)keyStore.getPrivateKey(operator);
		
		return new String( AsymmetricEncryption.decrypt(privateKey, message.getBytes(), algorithm) );
	}
	
	
	public boolean generateSymmetricSecurityKey(String uci){
		
		// generate the symmetric key
		SecretKey secretKey;
		
		try {
			secretKey = SymmetricEncryption.generateKey(SymmetricEncryption.AES);
			
			// store the security key
			keyStore.storeSecretKey(uci, secretKey, "password".toCharArray());
			
			return true;
		} catch (InvalidKeyException | KeyStoreException
				| NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
		}
		
		return false;
	}
	
	public String digestMessage(String message){
		return new String(MessageDigestOperations.encode(message.getBytes(), MessageDigestOperations.SHA1));
	}
	
	public PublicKey getPublicKey() {
		return (PublicKey) keyStore.getPublicKey(operator);
	}
	
	public PublicKey getPublicKey(String uci){
		return (PublicKey) keyStore.getPublicKey(uci);
	}
	
	public String getOperator() {
		return operator;
	}

	public void setOperator(String operator) {
		this.operator = operator;
	}

	public String getRegistrationRequestTime() {
		return registrationRequestTime;
	}

	public void setRegistrationRequestTime(String registrationRequestTime) {
		this.registrationRequestTime = registrationRequestTime;
	}

	public String getBootStrapUci() {
		return bootStrapUci;
	}

	public void setBootStrapUci(String bootStrapUci) {
		this.bootStrapUci = bootStrapUci;
	}
	
}

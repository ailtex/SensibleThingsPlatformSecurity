package se.sensiblethings.addinlayer.extensions.security;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.PKCS10CertificationRequest;

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
	private String bootStrapUci = null;
	
	private KeyStoreJCA keyStore = null;
	private Map<String, Object> dataPool = new HashMap<String, Object>();
	
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
		if(!keyStore.hasKey(uci)){
			// if not, create the key pair
			CreateKeyPairAndCertificate(uci);
		}
		
	}
	
	public String getOperator() {
		return operator;
	}

	public void setOperator(String operator) {
		this.operator = operator;
	}

	public String getBootStrapUci() {
		return bootStrapUci;
	}

	public void setBootStrapUci(String bootStrapUci) {
		this.bootStrapUci = bootStrapUci;
	}
	
	public void addToDataPool(String name, Object value){
		dataPool.put(name, value);
	}
	
	public Object getFromDataPool(String name){
		if(dataPool.containsKey(name)){
			return dataPool.get(name);
		}else{
			return null;
		}
	}
	
	public boolean removeFromDataPool(String name){
		if(dataPool.containsKey(name)){
			dataPool.remove(name);
			return true;
		}else{
			return false;
		}
	}
	
	/********************************************************************************
	 * 
	 *                           Certificate Part
	 ********************************************************************************/
	
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
		// setting the subject name of the certificate
		// String subjectName = "CN=" + uci + ",OU=ComputerColleage,O=MIUN,C=Sweden";
		String subjectName = uci;
		
		Certificate cert = CertificateOperations.generateSelfSignedcertificate(subjectName, keyPair);
		
		try {
			// store the private key with the self signed certificate
			keyStore.storePrivateKey(uci, keyPair.getPrivate(), "password".toCharArray(), new Certificate[]{cert});
			
			// store the self signed certificate
			keyStore.storeCertification(uci, cert, "password".toCharArray());
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
	}
	
	public boolean isCeritificateSigningRequestValid(
			PKCS10CertificationRequest certRequest, String fromUci) {

		try {
			if (certRequest.verify()
					&& certRequest.getCertificationRequestInfo().getSubject()
							.equals(fromUci)) {
				return true;
			} else {
				return false;
			}
		} catch (InvalidKeyException | NoSuchAlgorithmException
				| NoSuchProviderException | SignatureException e) {

			e.printStackTrace();
		}
		return false;
	}
	
	public Certificate[] signCertificateSigningRequest(PKCS10CertificationRequest certRequest, String uci){
		KeyPair keyPair = new KeyPair((PublicKey)keyStore.getPublicKey(operator), 
									  (PrivateKey)keyStore.getPrivateKey(operator, "password".toCharArray()));
		Certificate[] certs = null;
		
		try {
			certs =  CertificateOperations.buildChain(certRequest, (X509Certificate)keyStore.getCertificate(operator), keyPair);
			
			// store the issued certificate into keystore
			keyStore.storeCertification(uci, certs[0], "password".toCharArray());
			
		} catch (InvalidKeyException | CertificateParsingException
				| NoSuchAlgorithmException | NoSuchProviderException
				| SignatureException | KeyStoreException e) {
			
			e.printStackTrace();
		}
		
		return certs;
	}
	
	/**
	 * Get self signed certificate
	 * @return
	 */
	public Certificate getCertificate(){
		try {
			return keyStore.getCertificate(operator);
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		
		return null;
	}
	
	public Certificate getCertificate(String uci){
		try {
			return keyStore.getCertificate(uci);
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		
		return null;
	}
	
	@SuppressWarnings("deprecation")
	public PKCS10CertificationRequest getCertificateSigingRequest(String uci){
		String subjectName = "CN=" + uci + ",OU=ComputerColleage,O=MIUN,C=Sweden";
		
		KeyPair keyPair = new KeyPair((PublicKey)keyStore.getPublicKey(uci), 
									  (PrivateKey)keyStore.getPrivateKey(uci,  "password".toCharArray()));
		
		return CertificateOperations.generateCertificateSigningRequest(subjectName, keyPair);
	}
	
	public void storeCertificateChain(String uci, Certificate[] certs, String password){
		try {
			keyStore.storePrivateKey(uci, (PrivateKey)keyStore.getPrivateKey(uci, "password".toCharArray()),
					password.toCharArray(), certs);
		} catch (KeyStoreException e) {
			
			e.printStackTrace();
		}
	}
	
	/********************************************************************************
	 * 
	 *                           Signature Part
	 ********************************************************************************/
	
	
	public String signMessage(String message, String algorithm){
		// load the private key
		PrivateKey privateKey = (PrivateKey) keyStore.getPrivateKey(operator, "password".toCharArray());
		
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
	
	public boolean verifySignature(String message, String signature, Certificate cert, String algorithm){
		try {
			return SignatureOperations.verify(message.getBytes(), signature.getBytes(), cert, algorithm);
		} catch (InvalidKeyException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return false;
	}
	
	
	/********************************************************************************
	 * 
	 *                           Asymmetric Encrypt Part
	 ********************************************************************************/
	
	/**
	 * Encrypt message with RSA encryption
	 * @param message
	 * @param algorithm
	 * @return
	 */
	public String asymmetricEncryptMessage(String toUci, String message, String algorithm){
		
		return  new String (asymmetricEncryptMessage(toUci, message.getBytes(), algorithm));
	}
	
	public byte[] asymmetricEncryptMessage(String toUci, byte[] message, String algorithm){
		
		PublicKey publicKey = (PublicKey)keyStore.getPublicKey(toUci);
		
		return AsymmetricEncryption.encrypt(publicKey, message, algorithm);
	}
	
	/**
	 * Decrypt message with RSA encryption
	 * @param message
	 * @return
	 */
	public String asymmetricDecryptMessage(String message, String algorithm){
		return new String(asymmetricDecryptMessage(message.getBytes(), algorithm));
		
	}
	
	
	public byte[] asymmetricDecryptMessage(byte[] message, String algorithm){
		// load the private key
		PrivateKey privateKey = (PrivateKey)keyStore.getPrivateKey(operator, "password".toCharArray());
		
		return AsymmetricEncryption.decrypt(privateKey, message, algorithm);
	}
	
	public PublicKey getPublicKey() {
		return (PublicKey) keyStore.getPublicKey(operator);
	}
	
	public PublicKey getPublicKey(String uci){
		return (PublicKey) keyStore.getPublicKey(uci);
	}
	
	/********************************************************************************
	 * 
	 *                           Symmetric Encrypt Part
	 ********************************************************************************/
	
	public String symmetricEncryptMessage(String toUci, String message, String algorithm){
		
		return new String(symmetricEncryptMessage(toUci, message.getBytes(), algorithm));
	}
	
	public byte[] symmetricEncryptMessage(String toUci, byte[] message, String algorithm){
		// symmetric encryption
		SecretKey secretKey = (SecretKey) keyStore.getSecretKey(toUci, "password".toCharArray());
		byte[] plainText = null;
		try {
			plainText = SymmetricEncryption.encrypt(secretKey, message);
			
		} catch (InvalidKeyException | NoSuchAlgorithmException
				| NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException e) {
			e.printStackTrace();
		}

		return plainText;
	}
	
	public String symmetricDecryptMessage(String fromUci, String message, String algorithm){
		
		return new String(symmetricDecryptMessage(fromUci, message.getBytes(), algorithm));
	}
	
	public byte[] symmetricDecryptMessage(String fromUci, byte[] message, String algorithm){
		SecretKey secretKey = (SecretKey) keyStore.getSecretKey(fromUci, "password".toCharArray());
		
		byte[] plainText = null;
		try {
			plainText = SymmetricEncryption.decrypt(secretKey, message);
			
		} catch (InvalidKeyException | NoSuchAlgorithmException
				| NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException e) {
			e.printStackTrace();
		}

		return plainText;
	}
	
	public byte[] symmetricDecryptMessage(byte[] secretKey, byte[] message, String algorithm){
		// load the secret key
		SecretKey key = symmetricLoadKey(secretKey, algorithm);
		
		byte[] plainText = null;
		try {
			plainText = SymmetricEncryption.decrypt(key, message);
			
		} catch (InvalidKeyException | NoSuchAlgorithmException
				| NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException e2) {
			e2.printStackTrace();
		}

		return plainText;
	}
	
	private SecretKey symmetricLoadKey(byte[] secretKey, String algorithm){
		SecretKey key = null;
		
		try {
			key = (SecretKey)SymmetricEncryption.loadKey(secretKey, algorithm);
		} catch (InvalidKeyException | NoSuchAlgorithmException
				| InvalidKeySpecException e1) {
			e1.printStackTrace();
		}
		
		return key;
	}
	
	public boolean generateSymmetricSecurityKey(String uci){
		
		// generate the symmetric key
		SecretKey secretKey = null;
		
		try {
			secretKey = SymmetricEncryption.generateKey(SymmetricEncryption.AES);
			
			// store the security key
			storeSecretKey(uci, secretKey, "password");
			
			return true;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		return false;
	}
	
	public void storeSecretKey(String uci, SecretKey secretKey, String password){
		try {
			keyStore.storeSecretKey(uci, secretKey, password.toCharArray());
		} catch (InvalidKeyException | KeyStoreException
				| NoSuchAlgorithmException | InvalidKeySpecException e) {
			
			e.printStackTrace();
		}
	}
	
	public void storeSecretKey(String uci, byte[] secretKey, String algorithm, String password){
		SecretKey key = symmetricLoadKey(secretKey, algorithm);
		storeSecretKey(uci, key, password);
	}
	
	public Key getSecretKey(String uci, char[] password) {

		return keyStore.getSecretKey(uci, password);
	}
	
	public boolean hasSecretKey(String uci){
		return keyStore.hasKey(uci);
	}
	
	/********************************************************************************
	 * 
	 *                           Digest Part
	 ********************************************************************************/
	
	public String digestMessage(String message, String algorithm){
		
		return new String(MessageDigestOperations.encode(message.getBytes(), algorithm));
	}
	
}

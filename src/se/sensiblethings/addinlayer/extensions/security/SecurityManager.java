package se.sensiblethings.addinlayer.extensions.security;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Vector;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.bouncycastle.crypto.tls.SecurityParameters;
import org.bouncycastle.jce.PKCS10CertificationRequest;

import se.sensiblethings.addinlayer.extensions.security.certificate.CertificateOperations;
import se.sensiblethings.addinlayer.extensions.security.communication.SecureMessage;
import se.sensiblethings.addinlayer.extensions.security.configuration.SecurityConfiguration;
import se.sensiblethings.addinlayer.extensions.security.encryption.AsymmetricEncryption;
import se.sensiblethings.addinlayer.extensions.security.keystore.KeyStoreJCEKS;
import se.sensiblethings.addinlayer.extensions.security.keystore.IKeyStore;
import se.sensiblethings.addinlayer.extensions.security.messagedigest.MessageDigestOperations;
import se.sensiblethings.addinlayer.extensions.security.signature.SignatureOperations;
import se.sensiblethings.addinlayer.extensions.security.encryption.SymmetricEncryption;
import se.sensiblethings.interfacelayer.SensibleThingsNode;

public class SecurityManager {
	
	// the operator is the uci who owns
	private String myUci = null;
	private PublicKey publicKey = null;
	
	private KeyStoreJCEKS keyStore = null;
	private Map<String, Object> noncePool = null;
	private SecurityConfiguration config = null;
	
	public SecurityManager(SecurityConfiguration config){
		this.config = config;
		
		noncePool = new HashMap<String, Object>();
	}
	
	public void initializeKeyStore(String uci){
		setMyUci(uci);
		
		String prefix = uci.split("/")[0] + "_" + uci.split("/")[1];
		
		String filePath = config.getKeyStoreFileDirectory() + prefix
				+ "_" + config.getKeyStoreFileName();
		
		try {
			keyStore = new KeyStoreJCEKS(filePath, "password".toCharArray());
			
		} catch (IOException e) {
			// it may fail to load the key store
			e.printStackTrace();
		}
		
		// check weather the store has the KeyPair
		if(!keyStore.hasKey(uci)){
			// if not, create the key pair
			CreateKeyPairAndCertificate(uci);
		}
		
	}
	
	public void setSecuiryConfiguraton(SecurityConfiguration config){
		this.config = config;
	}
	
	public String getMyUci() {
		return myUci;
		
	}

	public void setMyUci(String myUci) {
		this.myUci = myUci;
	}

	
	public void addToNoncePool(String name, Object value){
		noncePool.put(name, value);
	}
	
	public Object getFromNoncePool(String name){
		
		return noncePool.get(name);
		
//		if(noncePool.containsKey(name)){
//			return noncePool.get(name);
//		}else{
//			return null;
//		}
	}
	
	public boolean removeFromNoncePool(String name){
		if(noncePool.containsKey(name)){
			noncePool.remove(name);
			return true;
		}else{
			return false;
		}
	}
	
	public boolean isSymmetricKeyValid(String uci, long lifeTime){
		return keyStore.hasSecretKey(uci) &&
				checkKeyLifetime(keyStore.getCreationData(uci), lifeTime);
	}
	
	private boolean checkKeyLifetime(Date creationTime, long lifeTime){
		long time = (new Date().getTime() - creationTime.getTime()) ;
		if(time < lifeTime){
			return true;
		}else{
			return false;
		}
		
	}
	
	
	public boolean isRegisted(String bootstrapUci){
		if(keyStore.getIssuredCertificate(bootstrapUci) == null){
			System.out.println("[" + myUci + "]" + "No issuered Certificate !");
			return false;
		}
		
		return keyStore.hasCertificate(bootstrapUci) && 
				keyStore.getIssuredCertificate(bootstrapUci).getIssuerX500Principal().getName().equals(bootstrapUci);
	}
	
	public String decapsulateSecureMessage(SecureMessage sm){
		byte[] payload = symmetricDecryptMessage(sm.fromUci, 
				sm.getPayload(), config.getSymmetricAlgorithm());
		
		return new String(payload);
	}
	
	
	
	public void encapsulateSecueMessage(Map<String, Vector<SecureMessage>> postOffice, String toUci) {
		if(postOffice.containsKey(toUci)){
			Iterator<SecureMessage> it = postOffice.get(toUci).iterator();
			while(it.hasNext()){
				SecureMessage sm = it.next();
				byte[] message = sm.getPayload();
				sm.setPayload(symmetricEncryptMessage(toUci, message, config.getSymmetricAlgorithm()));
				sm.setSignature(this.signMessage(message, config.getSignatureAlgorithm()));
				sm.setSignatureAlgorithm(config.getSignatureAlgorithm());
			}
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
			 keyPair = AsymmetricEncryption.generateKey(config.getAsymmetricAlgorithm(),
					 config.getAsymmetricKeyLength());
		} catch (NoSuchAlgorithmException e) {
			
			e.printStackTrace();
		}
		
		// generate the self signed X509 v1 certificate
		// setting the subject name of the certificate
		// String subjectName = "CN=" + uci + ",OU=ComputerColleage,O=MIUN,C=Sweden";
		String subjectName = uci;
		
		// set the life time to 1 year
		Certificate cert = CertificateOperations.generateSelfSignedcertificate(subjectName, 
				keyPair, config.getAsymmetricKeyLifetime());
		
		try {
			// store the private key with the self signed certificate
			keyStore.storePrivateKey(uci, keyPair.getPrivate(), "password".toCharArray(), 
					"password".toCharArray(), new Certificate[]{cert});
			
			// store the self signed certificate
			// keyStore.storeCertificate(uci, cert, "password".toCharArray());
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
	}
	
	public boolean isCeritificateSigningRequestValid(
		PKCS10CertificationRequest certRequest, String fromUci) {
		
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		// check the signature and the ID
		try {
			// verify the request using the BC provider
			if (certRequest.verify()
					&& certRequest.getCertificationRequestInfo().getSubject().equals(fromUci)) {
				return true;
			}
		} catch (InvalidKeyException | NoSuchAlgorithmException
				| NoSuchProviderException | SignatureException e) {

			e.printStackTrace();
		}
		return false;
	}
	
	public boolean isCertificateValid(Certificate cert, String fromUci){
		X509Certificate X509Cert = (X509Certificate) cert; 
		
		try {
			X509Cert.verify((PublicKey)keyStore.getPublicKey(config.getBootstrapUci()));
			X509Cert.checkValidity();
		} catch (InvalidKeyException | CertificateException
				| NoSuchAlgorithmException | NoSuchProviderException
				| SignatureException e) {
			
			e.printStackTrace();
			return false;
		}
		
		if(! X509Cert.getSubjectX500Principal().getName().equals(fromUci))
			return false;
		
		if(! X509Cert.getIssuerX500Principal().getName().equals(config.getBootstrapUci())){
			return false;
		}
			
		return true;
	}
	
	public boolean isContactedBefore(String fromUci){
		return keyStore.containAlias(fromUci);
	}
	
	public Certificate[] signCertificateSigningRequest(PKCS10CertificationRequest certRequest, String uci){
		KeyPair keyPair = new KeyPair((PublicKey)keyStore.getPublicKey(myUci), 
									  (PrivateKey)keyStore.getPrivateKey(myUci, "password".toCharArray()));
		Certificate[] certs = null;
		
		try {
			certs =  CertificateOperations.buildChain(certRequest, (X509Certificate)keyStore.getCertificate(myUci), keyPair, 
					config.getAsymmetricKeyLifetime());
			
			// store the issued certificate into keystore
			keyStore.storeCertificate(uci, certs[0], "password".toCharArray());
			
		} catch (InvalidKeyException | CertificateParsingException
				| NoSuchAlgorithmException | NoSuchProviderException
				| SignatureException | KeyStoreException e) {
			
			e.printStackTrace();
		}
		
		return certs;
	}
	
	/**
	 * Return itself certificate
	 * 
	 * Before registration to the bootstrap, it retrieves the self signed root certificate
	 * with X509V1 version. Otherwise, it retrieves the bootstrap issued certificate from the 
	 * certificate chain in the keystore's <code>PrivateKeyEntry</code>. It is the first certificate
	 * in this certificate chain.
	 * 
	 * @return Certificate itself certificate
	 */
	public Certificate getCertificate(){
		try {
			return keyStore.getCertificate(myUci);
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
	
	public boolean hasCertificate(String uci){
		return keyStore.hasCertificate(uci);
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
			
			keyStore.storePrivateKey(uci, (PrivateKey)keyStore.getPrivateKey(uci, password.toCharArray()),
					password.toCharArray(),password.toCharArray(), certs);
		} catch (KeyStoreException e) {
			
			e.printStackTrace();
		}
	}
	
	public void storeCertificate(String uci, Certificate cert, String password){
		
		try {
			keyStore.storeCertificate(uci, cert, password.toCharArray());
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
	}
	
	/********************************************************************************
	 * 
	 *                           Signature Part
	 ********************************************************************************/
	
	
	public String signMessage(String message, String algorithm){
		
		return new String(signMessage(message.getBytes(), algorithm));
	}
	
	public byte[] signMessage(byte[] message, String algorithm){
		// load the private key
		PrivateKey privateKey = (PrivateKey) keyStore.getPrivateKey(myUci, "password".toCharArray());
		
		byte[] signature = null;
		try {
			signature = SignatureOperations.sign(message, privateKey, algorithm);
		} catch (InvalidKeyException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		return signature;
	}
	
	public boolean verifySignature(byte[] message, byte[] signature, String fromUci, String algorithm){
		return verifySignature(message, signature, (PublicKey)keyStore.getPublicKey(fromUci), algorithm);
	}
	
	public boolean verifySignature(byte[] message, byte[] signature, PublicKey publicKey, String algorithm){
		try {
			return SignatureOperations.verify(message, signature, publicKey, algorithm);
		} catch (InvalidKeyException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return false;
	}
	
	public boolean verifySignature(String message, String signature, PublicKey publicKey, String algorithm){
		
		return verifySignature(message.getBytes(),  signature.getBytes(), publicKey, algorithm);
	}
	
	public boolean verifySignature(byte[] message, byte[] signature, Certificate cert, String algorithm){
		try {
			return SignatureOperations.verify(message, signature, cert, algorithm);
		} catch (InvalidKeyException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return false;
	}
	
	public boolean verifySignature(String message, String signature, Certificate cert, String algorithm){
		return verifySignature(message.getBytes(), signature.getBytes(), cert, algorithm);
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
		PrivateKey privateKey = (PrivateKey)keyStore.getPrivateKey(myUci, "password".toCharArray());
		
		return AsymmetricEncryption.decrypt(privateKey, message, algorithm);
	}
	
	public PublicKey getPublicKey() {
		return (PublicKey) keyStore.getPublicKey(myUci);
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
			plainText = SymmetricEncryption.encrypt(secretKey, message, config.getSymmetricMode());
			
		} catch (InvalidKeyException | NoSuchAlgorithmException
				| NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException | InvalidAlgorithmParameterException e) {
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
			plainText = SymmetricEncryption.decrypt(secretKey, message, config.getSymmetricMode());
			
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
			plainText = SymmetricEncryption.decrypt(key, message, config.getSymmetricMode());
			
		} catch (InvalidKeyException | NoSuchAlgorithmException
				| NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException e2) {
			e2.printStackTrace();
		}

		return plainText;
	}
	
	private SecretKey symmetricLoadKey(byte[] secretKey, String algorithm){
		SecretKey key = null;
		
		key = (SecretKey)SymmetricEncryption.loadKey(secretKey, algorithm);
		
		return key;
	}
	
	public boolean generateSymmetricSecurityKey(String uci){
		
		// generate the symmetric key
		SecretKey secretKey = null;
		
		try {
			secretKey = SymmetricEncryption.generateKey(config.getSymmetricAlgorithm(),  
					config.getSymmetricKeyLength());
			
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
			keyStore.storeSecretKey(uci, secretKey, password.toCharArray(), password.toCharArray());
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

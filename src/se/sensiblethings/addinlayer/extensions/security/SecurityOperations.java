package se.sensiblethings.addinlayer.extensions.security;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import se.sensiblethings.addinlayer.extensions.security.encryption.RSAEncryption;
import se.sensiblethings.addinlayer.extensions.security.keystore.DatabaseTemplate;
import se.sensiblethings.addinlayer.extensions.security.keystore.SQLiteDatabase;
import se.sensiblethings.addinlayer.extensions.security.messagedigest.MessageDigestOperations;

public class SecurityOperations {
	public static final String PublickKeyEncryption = "Public";
	public static final String SymmetricEncryption = "Symmetric";
	
	private String publicKey = null;

	// the operator is the uci who owns
	private String operator = null;
	
	private String registrationRequestTime = null;
	
	private String bootStrapUci = null;
	
	DatabaseTemplate db = null;
	
	public SecurityOperations(){
		db = new SQLiteDatabase();
		// firstly connect to permanent key store
		db.getConnection(SQLiteDatabase.PKS_DB_URL);
		//initial the database
		db.configureAndInitialize();
	}
	
	public void initializePermanentKeyStore(String uci){
		setOperator(uci);
		
		if(!db.hasKeyPair(uci)){
			db.createKeyPair(uci);
		}
	}
	
	public String signMessage(String message){
		RSAEncryption rsa = new RSAEncryption();
		
		// load the private key
		RSAPrivateKey privateKey = (RSAPrivateKey)rsa.loadKey(db.getPrivateKey(operator), rsa.privateKey);
		
		return new String(rsa.sign(privateKey, message.getBytes()));

	}
	
	public boolean verifyRequest(String signature, String publicKey){
		RSAEncryption rsa = new RSAEncryption();
		RSAPrivateKey key = (RSAPrivateKey)rsa.loadKey(publicKey.getBytes(), rsa.publicKey);
		
		String[] signaturePlainText = new String(rsa.decrypt(key, signature.getBytes())).split(",");
		if(signaturePlainText[0].equals(bootStrapUci) && signaturePlainText[1].equals(registrationRequestTime)){
			return true;
		}else{
			return false;
		}
	}
	
	// public key encryption
	public String encryptMessage(String message, String publicKey){
		RSAEncryption rsa = new RSAEncryption();
		
		RSAPublicKey key = (RSAPublicKey)rsa.loadKey(publicKey.getBytes(), rsa.publicKey);
		return new String(rsa.encrypt(key, message.getBytes()));
		/*
		if(type.equals(PublickKeyEncryption)){
			
			
		}else if(type.equals(SymmetricEncryption)){
			
		}
		return null;
		*/
	}
	
	public String decryptMessage(String message){
		RSAEncryption rsa = new RSAEncryption();
		
		RSAPrivateKey key = (RSAPrivateKey)rsa.loadKey(db.getPrivateKey(operator), rsa.privateKey);
		
		return new String(rsa.decrypt(key, message.getBytes()));
	}
	
	public String digestMessage(String message){
		return new String(MessageDigestOperations.encode(message.getBytes(), MessageDigestOperations.SHA1));
	}
	
	public String getPublicKey() {
		if(publicKey != null)
			publicKey = new String(db.getPublicKey(operator));
		return publicKey;
	}

	public void setPublicKey(String publicKey) {
		this.publicKey = publicKey;
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

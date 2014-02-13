package se.sensiblethings.addinlayer.extensions.security.keystore;

import java.util.Date;


public interface DatabaseOperations {
	public boolean getConnection(String databaseURL);
	
	public boolean configureAndInitialize();
	
	public boolean createPermanetKeyStore();
	
	public boolean createTemporaryKeyStore();
	
	public byte[] getPublicKey(String uci);
	
	public boolean storePublicKey(String uci, byte[] publicKey);
	
	public boolean storeCertification(String uci,  byte[] publicKey, String certification, Date validation);
	
	public boolean closeDatabase();
}
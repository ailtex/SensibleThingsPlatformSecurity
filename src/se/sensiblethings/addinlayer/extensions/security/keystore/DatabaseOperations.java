package se.sensiblethings.addinlayer.extensions.security.keystore;

import java.util.Date;


public interface DatabaseOperations {
	public boolean getConnection(String databaseURL);
	
	public boolean configureAndInitialize();
	
	public byte[] getPublicKey(String uci);
	
	public byte[] getPrivateKey(String uci);
	
	public boolean storePublicKey(String uci, byte[] publicKey);
	
	public boolean storeCertification(String uci,  byte[] publicKey, String certification, Date validation);
	
	public boolean closeDatabase();

	public boolean hasKeyPair(String uci);

	public boolean createKeyPair(String uci);

}

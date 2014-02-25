package se.sensiblethings.addinlayer.extensions.security.keystore;

import java.security.Key;
import java.util.Date;


public interface KeyStoreTemplate {
	public boolean getConnection(String databaseURL);
	
	public boolean configureAndInitialize();
	
	public Key getPublicKey(String uci);
	
	public Key getPrivateKey(String uci);
	
	public boolean storePublicKey(String uci, byte[] publicKey);
	
	public boolean storeCertification(String uci,  byte[] publicKey, String certification, Date validation);
	
	public boolean closeDatabase();

	public boolean hasKeyPair(String uci);

}

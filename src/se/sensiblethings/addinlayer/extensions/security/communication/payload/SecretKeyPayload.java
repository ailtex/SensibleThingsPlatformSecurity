package se.sensiblethings.addinlayer.extensions.security.communication.payload;

import javax.crypto.SecretKey;

import se.sensiblethings.addinlayer.extensions.security.communication.MessagePayload;


public class SecretKeyPayload extends MessagePayload{

	/**
	 * 
	 */
	private static final long serialVersionUID = 8845829119915708208L;
	
	private SecretKey key = null;
	private String algorithm = null;
	private long lifeTime = 0;
	private String fromUci = null;
	private int nonce;
	
	public SecretKeyPayload(SecretKey key, String algorithm, long lifeTime) {
		super();
		this.key = key;
		this.algorithm = algorithm;
		this.lifeTime = lifeTime;
	}


	public SecretKey getKey() {
		return key;
	}


	public void setKey(SecretKey key) {
		this.key = key;
	}


	public String getAlgorithm() {
		return algorithm;
	}


	public void setAlgorithm(String algorithm) {
		this.algorithm = algorithm;
	}


	public long getLifeTime() {
		return lifeTime;
	}


	public void setLifeTime(long lifeTime) {
		this.lifeTime = lifeTime;
	}


	public String getFromUci() {
		return fromUci;
	}


	public void setFromUci(String fromUci) {
		this.fromUci = fromUci;
	}


	public int getNonce() {
		return nonce;
	}


	public void setNonce(int nonce) {
		this.nonce = nonce;
	}

}
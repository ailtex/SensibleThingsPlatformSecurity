package se.sensiblethings.addinlayer.extensions.security.communication;

import se.sensiblethings.disseminationlayer.communication.Message;
import se.sensiblethings.interfacelayer.SensibleThingsNode;

public class CertificateResponseMessage extends Message{
	
	// contain the session symmetric key encrypt by the public key of applicant
	private byte[] encryptSecretKey = null;
	
	private byte[] payload = null;
	
	public String fromUci;
	public String toUci;
	
	public CertificateResponseMessage(String toUci, String fromUci, SensibleThingsNode toNode,
			SensibleThingsNode fromNode) {
		super(fromNode, toNode);
		
		this.fromUci = fromUci;
		this.toUci = toUci;
	}

	public byte[] getEncryptSecretKey() {
		return encryptSecretKey;
	}

	public void setEncryptSecretKey(byte[] encryptSecretKey) {
		this.encryptSecretKey = encryptSecretKey;
	}

	public byte[] getPayload() {
		return payload;
	}

	public void setPayload(byte[] payload) {
		this.payload = payload;
	}

	
}

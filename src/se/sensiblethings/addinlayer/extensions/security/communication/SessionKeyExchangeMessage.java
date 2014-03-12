package se.sensiblethings.addinlayer.extensions.security.communication;

import se.sensiblethings.disseminationlayer.communication.Message;
import se.sensiblethings.interfacelayer.SensibleThingsNode;

public class SessionKeyExchangeMessage extends Message{

	/**
	 * 
	 */
	private static final long serialVersionUID = -8794411419942450449L;
	
	public String toUci;
	public String fromUci;
	
	private byte[] secretKeyPayload;
	private byte[] secretKeyPayloadSignature;
	private byte[] certificatePayload;
	
	public SessionKeyExchangeMessage(String toUci, String fromUci, SensibleThingsNode toNode,
			SensibleThingsNode fromNode) {
		super(fromNode, toNode);
		
		this.fromUci = fromUci;
		this.toUci = toUci;
	}

	public byte[] getSecretKeyPayload() {
		return secretKeyPayload;
	}

	public void setSecretKeyPayload(byte[] secretKeyPayload) {
		this.secretKeyPayload = secretKeyPayload;
	}

	public byte[] getCertificatePayload() {
		return certificatePayload;
	}

	public void setCertificatePayload(byte[] certificatePayload) {
		this.certificatePayload = certificatePayload;
	}

	public byte[] getSecretKeyPayloadSignature() {
		return secretKeyPayloadSignature;
	}

	public void setSecretKeyPayloadSignature(byte[] secretKeyPayloadSignature) {
		this.secretKeyPayloadSignature = secretKeyPayloadSignature;
	}
	
	
}

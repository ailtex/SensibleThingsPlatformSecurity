package se.sensiblethings.addinlayer.extensions.security.communication.message;

import se.sensiblethings.addinlayer.extensions.security.communication.SecureMessage;
import se.sensiblethings.disseminationlayer.communication.Message;
import se.sensiblethings.interfacelayer.SensibleThingsNode;

public class SessionKeyExchangeMessage extends SecureMessage{

	/**
	 * 
	 */
	private static final long serialVersionUID = -8794411419942450449L;
		
	private byte[] certificatePayload;
	
	public SessionKeyExchangeMessage(String toUci, String fromUci, SensibleThingsNode toNode,
			SensibleThingsNode fromNode) {
		super(toUci, fromUci, fromNode, toNode);
	}

	public byte[] getCertificatePayload() {
		return certificatePayload;
	}

	public void setCertificatePayload(byte[] certificatePayload) {
		this.certificatePayload = certificatePayload;
	}

}

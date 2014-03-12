package se.sensiblethings.addinlayer.extensions.security.communication;

import se.sensiblethings.disseminationlayer.communication.Message;
import se.sensiblethings.interfacelayer.SensibleThingsNode;

public class CertificateAcceptedResponseMessage extends Message{


	private static final long serialVersionUID = 259454408800180536L;
	
	public String fromUci;
	public String toUci;
	
	private byte[] payload;
	
	public CertificateAcceptedResponseMessage(String toUci, String fromUci, SensibleThingsNode toNode,
			SensibleThingsNode fromNode) {
		super(fromNode, toNode);
		
		this.fromUci =fromUci;
		this.toUci = toUci;
	}

	public byte[] getPayload() {
		return payload;
	}

	public void setPayload(byte[] payload) {
		this.payload = payload;
	}
	
}

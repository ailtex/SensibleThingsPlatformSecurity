package se.sensiblethings.addinlayer.extensions.security.communication;

import se.sensiblethings.disseminationlayer.communication.Message;
import se.sensiblethings.interfacelayer.SensibleThingsNode;

public class SecureMessage extends Message{
	
	public String fromUci;
	public String toUci;
	
	private String payload;
	private byte[] signature;
	private String signatureAlgorithm;
	
	
	public SecureMessage(String toUci, String fromUci, SensibleThingsNode toNode,
			SensibleThingsNode fromNode) {
		super(fromNode, toNode);
		
		this.fromUci =fromUci;
		this.toUci = toUci;
	}

	public String getPayload() {
		return payload;
	}

	public void setPayload(String payload) {
		this.payload = payload;
	}
	
}

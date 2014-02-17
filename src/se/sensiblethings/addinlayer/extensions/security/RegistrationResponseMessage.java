package se.sensiblethings.addinlayer.extensions.security;

import se.sensiblethings.disseminationlayer.communication.Message;
import se.sensiblethings.interfacelayer.SensibleThingsNode;

public class RegistrationResponseMessage extends Message{


	private static final long serialVersionUID = -455090768499986394L;
	private String publicKey;
	private String signatue;
	
	public String uci;
	
	public RegistrationResponseMessage(String uci, SensibleThingsNode toNode,
			SensibleThingsNode fromNode) {
		super(fromNode, toNode);
		
		this.uci = uci;
	}

	public String getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(String publicKey) {
		this.publicKey = publicKey;
	}

	public String getSignatue() {
		return signatue;
	}

	public void setSignatue(String signatue) {
		this.signatue = signatue;
	}
	
	
}

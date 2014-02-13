package se.sensiblethings.addinlayer.extensions.security;

import se.sensiblethings.disseminationlayer.communication.Message;
import se.sensiblethings.interfacelayer.SensibleThingsNode;

public class RegistrationResponseMessage extends Message{


	private static final long serialVersionUID = -455090768499986394L;
	private byte[] publicKey;
	
	public String uci;
	
	public RegistrationResponseMessage(String uci, SensibleThingsNode toNode,
			SensibleThingsNode fromNode) {
		super(fromNode, toNode);
		
		this.uci = uci;
	}
	

}

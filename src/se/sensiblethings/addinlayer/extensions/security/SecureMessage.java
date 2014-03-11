package se.sensiblethings.addinlayer.extensions.security;

import se.sensiblethings.disseminationlayer.communication.Message;
import se.sensiblethings.interfacelayer.SensibleThingsNode;

public class SecureMessage extends Message{
	
	public String fromUci;
	public String toUci;
	
	public SecureMessage(String toUci, String fromUci, SensibleThingsNode toNode,
			SensibleThingsNode fromNode) {
		super(fromNode, toNode);
		
		this.fromUci =fromUci;
		this.toUci = toUci;
	}

}

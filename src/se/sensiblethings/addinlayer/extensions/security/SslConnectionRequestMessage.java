package se.sensiblethings.addinlayer.extensions.security;

import se.sensiblethings.disseminationlayer.communication.Message;
import se.sensiblethings.interfacelayer.SensibleThingsNode;

public class SslConnectionRequestMessage extends Message{

	/**
	 * 
	 */
	private static final long serialVersionUID = 7758694573355260412L;
	
	public String uci;
	
	public SslConnectionRequestMessage(String uci, SensibleThingsNode toNode,
			SensibleThingsNode fromNode) {
		super(fromNode, toNode);
		
		this.uci = uci;
	}

}

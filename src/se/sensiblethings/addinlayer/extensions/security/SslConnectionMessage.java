package se.sensiblethings.addinlayer.extensions.security;

import se.sensiblethings.disseminationlayer.communication.Message;
import se.sensiblethings.interfacelayer.SensibleThingsNode;

public class SslConnectionMessage extends Message{

	/**
	 * 
	 */
	private static final long serialVersionUID = 7758694573355260412L;
	
	public String uci;
	
	private String signal;
	
	public SslConnectionMessage(String uci, SensibleThingsNode toNode,
			SensibleThingsNode fromNode) {
		super(fromNode, toNode);
		
		this.uci = uci;
	}

	public String getSignal() {
		return signal;
	}

	public void setSignal(String signal) {
		this.signal = signal;
	}
	
	
}

package se.sensiblethings.addinlayer.extensions.security.communication;

import java.io.Serializable;

public class MessagePayload implements Serializable{

	private static final long serialVersionUID = 5874936569615329921L;
	
	public String fromUci;
	public String toUci;
	
	public MessagePayload(){}
	
	public MessagePayload(String fromUci, String toUci) {
		this.fromUci = fromUci;
		this.toUci = toUci;
	}
		
}

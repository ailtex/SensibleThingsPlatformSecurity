package se.sensiblethings.addinlayer.extensions.security.communication;

import java.util.Date;

import se.sensiblethings.disseminationlayer.communication.Message;
import se.sensiblethings.interfacelayer.SensibleThingsNode;

public class RegistrationRequestMessage extends Message{

	private static final long serialVersionUID = -7196963283243573690L;

	public String fromUci;
	public String toUci;
	
	private String registrationRequestTime = null;
	
	public String getRegistrationRequestTime() {
		return registrationRequestTime;
	}

	public void setRegistrationRequestTime(String registrationRequestTime) {
		this.registrationRequestTime = registrationRequestTime;
	}
	
	public RegistrationRequestMessage(String toUci, String fromUci, SensibleThingsNode toNode,
			SensibleThingsNode fromNode){
		super(fromNode, toNode);

		this.fromUci = fromUci;
		this.toUci = toUci;
		
		this.registrationRequestTime = new Date().toString();
	}
	
	public RegistrationRequestMessage(String toUci, String fromUci, SensibleThingsNode toNode,
			SensibleThingsNode fromNode, String registrationRequestTime){
		super(fromNode, toNode);
		
		this.fromUci = fromUci;
		this.toUci = toUci;
		
		this.registrationRequestTime = registrationRequestTime;
	}
}

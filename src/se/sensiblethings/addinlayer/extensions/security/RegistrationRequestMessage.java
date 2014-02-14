package se.sensiblethings.addinlayer.extensions.security;

import java.util.Date;

import se.sensiblethings.disseminationlayer.communication.Message;
import se.sensiblethings.interfacelayer.SensibleThingsNode;

public class RegistrationRequestMessage extends Message{

	private static final long serialVersionUID = -7196963283243573690L;

	public String fromUci;
	public String toUci;
	
	public String registrationRequest;
	
	public String getRegistrationRequest() {
		return registrationRequest;
	}

	public void setRegistrationRequest(String registrationRequest) {
		this.registrationRequest = registrationRequest;
	}
	
	public RegistrationRequestMessage(String toUci, String fromUci, SensibleThingsNode toNode,
			SensibleThingsNode fromNode){
		super(fromNode, toNode);

		this.fromUci = fromUci;
		this.toUci = toUci;
		
		this.registrationRequest = new Date().toString();
	}
	
	public RegistrationRequestMessage(String toUci, String fromUci, SensibleThingsNode toNode,
			SensibleThingsNode fromNode, String registrationRequest){
		super(fromNode, toNode);
		
		this.fromUci = fromUci;
		this.toUci = toUci;
		
		this.registrationRequest = registrationRequest;
	}
}

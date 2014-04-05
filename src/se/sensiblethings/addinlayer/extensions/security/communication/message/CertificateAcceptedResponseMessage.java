package se.sensiblethings.addinlayer.extensions.security.communication.message;

import se.sensiblethings.addinlayer.extensions.security.communication.SecureMessage;
import se.sensiblethings.disseminationlayer.communication.Message;
import se.sensiblethings.interfacelayer.SensibleThingsNode;

public class CertificateAcceptedResponseMessage extends SecureMessage{


	private static final long serialVersionUID = 259454408800180536L;
	
	
	public CertificateAcceptedResponseMessage(String toUci, String fromUci, SensibleThingsNode toNode,
			SensibleThingsNode fromNode) {
		super(toUci, fromUci, toNode, fromNode);
		
	}
	
}

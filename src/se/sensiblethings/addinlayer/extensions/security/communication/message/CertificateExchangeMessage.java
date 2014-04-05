package se.sensiblethings.addinlayer.extensions.security.communication.message;

import java.util.Date;

import se.sensiblethings.addinlayer.extensions.security.communication.SecureMessage;
import se.sensiblethings.interfacelayer.SensibleThingsNode;

public class CertificateExchangeMessage extends SecureMessage{
		
	public CertificateExchangeMessage(String toUci, String fromUci,
			SensibleThingsNode toNode, SensibleThingsNode fromNode) {
		super(toUci, fromUci, toNode, fromNode);
		
	}

}

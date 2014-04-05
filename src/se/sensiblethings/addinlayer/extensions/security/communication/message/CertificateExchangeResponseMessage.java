package se.sensiblethings.addinlayer.extensions.security.communication.message;

import java.security.cert.Certificate;

import se.sensiblethings.addinlayer.extensions.security.communication.SecureMessage;
import se.sensiblethings.interfacelayer.SensibleThingsNode;

public class CertificateExchangeResponseMessage extends SecureMessage{
	
	/**
	 * 
	 */
	private static final long serialVersionUID = -4978617651995412001L;
	
	public CertificateExchangeResponseMessage(String toUci, String fromUci,
			SensibleThingsNode toNode, SensibleThingsNode fromNode) {
		super(toUci, fromUci, toNode, fromNode);
	}
	
}

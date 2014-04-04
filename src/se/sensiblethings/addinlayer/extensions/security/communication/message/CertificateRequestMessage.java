package se.sensiblethings.addinlayer.extensions.security.communication.message;

import org.bouncycastle.jce.PKCS10CertificationRequest;

import se.sensiblethings.addinlayer.extensions.security.communication.SecureMessage;
import se.sensiblethings.disseminationlayer.communication.Message;
import se.sensiblethings.interfacelayer.SensibleThingsNode;

public class CertificateRequestMessage extends SecureMessage{

	private static final long serialVersionUID = -3858164569571353606L;
	
	public CertificateRequestMessage(String toUci, String fromUci, SensibleThingsNode toNode,
			SensibleThingsNode fromNode) {
		
		super(toUci, fromUci, fromNode, toNode);
		
	}

}

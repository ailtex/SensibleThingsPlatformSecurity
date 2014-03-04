package se.sensiblethings.addinlayer.extensions.security;

import se.sensiblethings.disseminationlayer.communication.Message;
import se.sensiblethings.interfacelayer.SensibleThingsNode;

public class CertificateRequestMessage extends Message{

	private static final long serialVersionUID = -3858164569571353606L;
	
	private String content = null;
	private PKCS10CertificationRequest certRequest = null;
	
	public String fromUci;
	public String toUci;
	
	
	public CertificateRequestMessage(String toUci, String fromUci, SensibleThingsNode toNode,
			SensibleThingsNode fromNode) {
		super(fromNode, toNode);
		
	}

	public String getContent() {
		return content;
	}

	public void setContent(String content) {
		this.content = content;
	}
}

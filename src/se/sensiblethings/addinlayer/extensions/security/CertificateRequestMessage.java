package se.sensiblethings.addinlayer.extensions.security;

import org.bouncycastle.jce.PKCS10CertificationRequest;

import se.sensiblethings.disseminationlayer.communication.Message;
import se.sensiblethings.interfacelayer.SensibleThingsNode;

public class CertificateRequestMessage extends Message{

	private static final long serialVersionUID = -3858164569571353606L;
	
	
	private PKCS10CertificationRequest certRequest = null;
	private int noce;
	
	public String fromUci;
	public String toUci;
	
	public CertificateRequestMessage(String toUci, String fromUci, SensibleThingsNode toNode,
			SensibleThingsNode fromNode) {
		super(fromNode, toNode);
		
	}

	public PKCS10CertificationRequest getCertRequest() {
		return certRequest;
	}

	public void setCertRequest(PKCS10CertificationRequest certRequest) {
		this.certRequest = certRequest;
	}
	
	public int getNoce() {
		return noce;
	}

	public void setNoce(int noce) {
		this.noce = noce;
	}
}

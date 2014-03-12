package se.sensiblethings.addinlayer.extensions.security.communication;

import java.security.cert.Certificate;

import se.sensiblethings.disseminationlayer.communication.Message;
import se.sensiblethings.interfacelayer.SensibleThingsNode;

public class RegistrationResponseMessage extends Message{


	private static final long serialVersionUID = -455090768499986394L;
	private Certificate cert;
	private String signature;
	private String signatureAlgorithm;
	
	public String uci;
	
	public RegistrationResponseMessage(String uci, SensibleThingsNode toNode,
			SensibleThingsNode fromNode) {
		super(fromNode, toNode);
		
		this.uci = uci;
	}

	public Certificate getCertificate() {
		return cert;
	}

	public void setCertificate(Certificate cert) {
		this.cert = cert;
	}

	public String getSignature() {
		return signature;
	}

	public void setSignatue(String signature) {
		this.signature = signature;
	}

	public String getSignatureAlgorithm() {
		return signatureAlgorithm;
	}

	public void setSignatureAlgorithm(String signatureAlgorithm) {
		this.signatureAlgorithm = signatureAlgorithm;
	}
	
	
}

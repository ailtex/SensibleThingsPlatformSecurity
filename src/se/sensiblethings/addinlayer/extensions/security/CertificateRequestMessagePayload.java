package se.sensiblethings.addinlayer.extensions.security;

import java.io.Serializable;

import org.bouncycastle.jce.PKCS10CertificationRequest;

import se.sensiblethings.addinlayer.extensions.security.communication.MessagePayload;

public class CertificateRequestMessagePayload extends MessagePayload{

	private static final long serialVersionUID = -7246290917557264390L;
	
	private PKCS10CertificationRequest certRequest = null;
	private int nonce;
	
	public CertificateRequestMessagePayload(PKCS10CertificationRequest certRequest,int nonce ){
		this.certRequest = certRequest;
		this.nonce = nonce;
	}
	public PKCS10CertificationRequest getCertRequest() {
		return certRequest;
	}

	public void setCertRequest(PKCS10CertificationRequest certRequest) {
		this.certRequest = certRequest;
	}
	
	public int getNonce() {
		return nonce;
	}

	public void setNonce(int nonce) {
		this.nonce = nonce;
	}

}

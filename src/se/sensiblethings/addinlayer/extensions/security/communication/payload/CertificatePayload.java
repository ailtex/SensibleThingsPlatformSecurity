package se.sensiblethings.addinlayer.extensions.security.communication.payload;

import java.security.cert.Certificate;

import se.sensiblethings.addinlayer.extensions.security.communication.MessagePayload;


public class CertificatePayload extends MessagePayload{

	/**
	 * 
	 */
	private static final long serialVersionUID = -1698590742363565318L;
	
	private Certificate cert = null;
	
	
	public CertificatePayload(String fromUci, String toUci) {
		super(fromUci, toUci);
	}

	public Certificate getCert() {
		return cert;
	}

	public void setCert(Certificate cert) {
		this.cert = cert;
	}


	
}

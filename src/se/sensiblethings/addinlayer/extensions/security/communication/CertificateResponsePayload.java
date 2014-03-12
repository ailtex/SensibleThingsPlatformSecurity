package se.sensiblethings.addinlayer.extensions.security.communication;

import java.security.cert.Certificate;

public class CertificateResponsePayload extends MessagePayload{

	private static final long serialVersionUID = -2410288697653708987L;
	
	private Certificate[] certChain = null;
	private int fromNonce;
	private int toNonce;
	
	public Certificate[] getCertChain() {
		return certChain;
	}
	public void setCertChain(Certificate[] certChain) {
		this.certChain = certChain;
	}
	public int getFromNonce() {
		return fromNonce;
	}
	public void setFromNonce(int fromNonce) {
		this.fromNonce = fromNonce;
	}
	public int getToNonce() {
		return toNonce;
	}
	public void setToNonce(int toNonce) {
		this.toNonce = toNonce;
	}
	
}
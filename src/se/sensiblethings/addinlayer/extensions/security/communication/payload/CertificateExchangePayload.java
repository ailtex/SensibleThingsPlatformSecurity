package se.sensiblethings.addinlayer.extensions.security.communication.payload;

import java.security.cert.Certificate;
import java.util.Date;

public class CertificateExchangePayload extends CertificatePayload{

	/**
	 * 
	 */
	private static final long serialVersionUID = 129596739686835045L;
	
	private Date timeStamp = null;
	
	/*
	public CertificateExchangePayload(String fromUci, String toUci){
		super(fromUci, toUci);
	}
	*/
	
	public CertificateExchangePayload(String fromUci, String toUci) {
		super(fromUci, toUci);
	}

	public Date getTimeStamp() {
		return timeStamp;
	}

	public void setTimeStamp(Date timeStamp) {
		this.timeStamp = timeStamp;
	}
	
}

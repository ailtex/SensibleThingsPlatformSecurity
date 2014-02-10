package se.sensiblethings.addinlayer.extensions.security;

public interface SecurityListener {
	public void sslConnectionRequestResponse(String uci, String value);
}

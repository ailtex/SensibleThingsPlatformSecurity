package se.sensiblethings.addinlayer.extensions.security;

import se.sensiblethings.interfacelayer.SensibleThingsNode;

public interface SecurityListener {
	public void sslConnectionRequestEvent(String uci, SensibleThingsNode fromNode);
}

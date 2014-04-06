package se.sensiblethings.addinlayer.extensions.security.configuration;

import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.XMLConfiguration;
import org.apache.commons.configuration.tree.xpath.XPathExpressionEngine;

public class SecurityConfiguration {
	
	private int securityLevel;
	private XMLConfiguration config = null;
	
	public SecurityConfiguration(String filePath, int securityLevel){
		this.securityLevel = securityLevel;
		
		try {
			config =new XMLConfiguration(filePath);
			config.setExpressionEngine(new XPathExpressionEngine());

		} catch (ConfigurationException e) {
			e.printStackTrace();
		}

	}
	
	public void setSecurityLevel(int securityLevel) {
		this.securityLevel = securityLevel;
	}
	
	public int getSecurityLevel() {
		return securityLevel;
	}
	
	public String getBootstrapUci(){
		return config.getString("/bootstrap/uci");
	}
	
	public String getBootstrapIP(){
		return config.getString("/bootstrap/ip");
	}
	
	public String getBootstrapPort(){
		return config.getString("/bootstrap/port");
	}
	
	public String getKeyStoreFileName(){
		return config.getString("/keyStore/name");
	}
	
	public String getKeyStoreFileDirectory(){
		return config.getString("/keyStore/directory");
	}
	
	public String getSymmetricAlgorithm() {
		return config.getString("/security[level='" + String.valueOf(securityLevel) + "']/symmetric/algorithm" );
	}

	public String getSymmetricMode(){
		return config.getString("/security[level='" + String.valueOf(securityLevel) + "']/symmetric/mode" );
	}

	public int getSymmetricKeyLength() {
		return config.getInt("/security[level='" + String.valueOf(securityLevel) + "']/symmetric/key/length");
	}

	public long getSymmetricKeyLifeTime() {
		return config.getLong("/security[level='" + String.valueOf(securityLevel) + "']/symmetric/key/lifetime");
	}

	public String getAsymmetricAlgorithm() {
		return config.getString("/security[level='" + String.valueOf(securityLevel) + "']/asymmetric/algorithm" );
	}

	public int getAsymmetricKeyLength() {
		return config.getInt("/security[level='" + String.valueOf(securityLevel) + "']/asymmetric/key/length");
	}

	public long getAsymmetricKeyLifetime() {
		return config.getLong("/security[level='" + String.valueOf(securityLevel) + "']/asymmetric/key/lifetime");
	}
	
	public String getSignatureAlgorithm() {
		return config.getString("/security[level='" + String.valueOf(securityLevel) + "']/signature/algorithm" );
	}

	

}

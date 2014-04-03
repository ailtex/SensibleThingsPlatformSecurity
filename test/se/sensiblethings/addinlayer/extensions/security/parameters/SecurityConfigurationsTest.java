package se.sensiblethings.addinlayer.extensions.security.parameters;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import se.sensiblethings.addinlayer.extensions.security.configuration.SecurityConfiguration;

public class SecurityConfigurationsTest {

SecurityConfiguration config = null;
	
	@Before
	public void setUp() throws Exception {
		config = new SecurityConfiguration("config/SecurityConfiguration.xml", 1);
	}


	@Test
	public void testGetSecurityLevel() {
		assertSame(1,config.getSecurityLevel());
	}

	@Test
	public void testGetBootstrapUci() {
		assertEquals("bootstrap@miun.se", config.getBootstrapUci());
	}

	@Test
	public void testGetBootstrapIP() {
		assertEquals("", config.getBootstrapIP());
	}

	@Test
	public void testGetBootstrapPort() {
		assertEquals("9009", config.getBootstrapPort());
	}

	@Test
	public void testGetSymmetricAlgorithm() {
		assertEquals("AES", config.getSymmetricAlgorithm());
	}

	@Test
	public void testGetSymmetricMode() {
		assertEquals("AES/CBC/PKCS5Padding", config.getSymmetricMode());
	}

	@Test
	public void testGetSymmetricKeyLength() {
		int length = 128;
		assertEquals(length, config.getSymmetricKeyLength());
	}

	@Test
	public void testGetSymmetricKeyLifeTime() {
		assertEquals(24*60*60*1000L, config.getSymmetricKeyLifeTime());
	}

	@Test
	public void testGetAsymmetricAlgorithm() {
		assertEquals("RSA", config.getAsymmetricAlgorithm());
	}

	@Test
	public void testGetAsymmetricKeyLength() {
		int length = 1024;
		assertEquals(length, config.getAsymmetricKeyLength());
	}

	@Test
	public void testGetAsymmetricKeyLifetime() {
		assertEquals(365*24*60*60*1000L, config.getAsymmetricKeyLifetime());
	}

	@Test
	public void testGetSignatureAlgorithm() {
		assertEquals("SHA1withRSA",config.getSignatureAlgorithm());
	}

}

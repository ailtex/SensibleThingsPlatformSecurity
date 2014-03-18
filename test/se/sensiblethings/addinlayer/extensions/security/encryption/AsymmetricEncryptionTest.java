package se.sensiblethings.addinlayer.extensions.security.encryption;

import static org.junit.Assert.*;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import org.junit.Test;

public class AsymmetricEncryptionTest {

	@Test
	public void testGenerateKey() {
		AsymmetricEncryption encrypt = new AsymmetricEncryption();
		
        // Generate keys   
        KeyPair keyPair = null;
		try {
			keyPair = encrypt.generateKey("RSA", 2048);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
        
        assertTrue(keyPair != null);

	}

	@Test
	public void testLoadKeyByteArrayStringString() {
		fail("Not yet implemented");
	}

	@Test
	public void testEncrypt() {
		fail("Not yet implemented");
	}

	@Test
	public void testDecrypt() {
		fail("Not yet implemented");
	}

	@Test
	public void testSign() {
		fail("Not yet implemented");
	}

	@Test
	public void testSaveKey() {
		fail("Not yet implemented");
	}

	@Test
	public void testLoadKeyStringInt() {
		fail("Not yet implemented");
	}

}

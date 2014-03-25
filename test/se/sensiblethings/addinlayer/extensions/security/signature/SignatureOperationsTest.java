package se.sensiblethings.addinlayer.extensions.security.signature;

import static org.junit.Assert.*;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;

import org.junit.Before;
import org.junit.Test;

import se.sensiblethings.addinlayer.extensions.security.certificate.CertificateOperations;
import se.sensiblethings.addinlayer.extensions.security.encryption.AsymmetricEncryption;

public class SignatureOperationsTest {

	private KeyPair keyPair = null;
	
	@Before
	public void setUp() throws Exception {
		keyPair = AsymmetricEncryption.generateKey("RSA", 2048);
		
	}

	@Test
	public void testSign() {
		byte[] text = "Hello Sweden".getBytes();
		try {
			byte[] signature = SignatureOperations.sign(text, keyPair.getPrivate(), SignatureOperations.SHA256WITHRSA);
			assertTrue("[test Sign]", SignatureOperations.verify(text, signature, 
					keyPair.getPublic(), SignatureOperations.SHA256WITHRSA));
			
		} catch (InvalidKeyException | NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

	@Test
	public void testVerifyByteArrayByteArrayPublicKeyString() {
		byte[] text = "Hello Sweden".getBytes();
		try {
			byte[] signature = SignatureOperations.sign(text, keyPair.getPrivate(), SignatureOperations.SHA1WITHRSA);
			assertTrue("[test Sign]", SignatureOperations.verify(text, signature, 
					keyPair.getPublic(), SignatureOperations.SHA1WITHRSA));
			
		} catch (InvalidKeyException | NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Test
	public void testVerifyByteArrayByteArrayCertificateString() {
		byte[] text = "Hello Sweden".getBytes();
		Certificate cert = CertificateOperations.generateSelfSignedcertificate("CN=Bootstrap", keyPair, 1000*60*60*24);
		
		try {
			byte[] signature = SignatureOperations.sign(text, keyPair.getPrivate(), SignatureOperations.SHA256WITHRSA);
			assertTrue("[test Sign]", SignatureOperations.verify(text, signature, 
					cert, SignatureOperations.SHA256WITHRSA));
			
		} catch (InvalidKeyException | NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}

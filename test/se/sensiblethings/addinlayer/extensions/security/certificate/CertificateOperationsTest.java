package se.sensiblethings.addinlayer.extensions.security.certificate;

import static org.junit.Assert.*;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.junit.Before;
import org.junit.Test;

import se.sensiblethings.addinlayer.extensions.security.encryption.AsymmetricEncryption;

public class CertificateOperationsTest {

	private KeyPair keyPair = null;
	private long lifeTime = 365*24*60*60*1000;
	
	@Before
	public void setUp() throws Exception {
		keyPair = AsymmetricEncryption.generateKey("RSA", 1024);
	}

	@Test
	public void testGenerateSelfSignedcertificate() {
		String subjectName = "Cn=Bootstrap";
		Certificate cert = CertificateOperations.generateSelfSignedcertificate(subjectName, keyPair, 1000);
		//System.out.println(cert.toString());
		
		try {
			cert.verify(keyPair.getPublic());
		} catch (InvalidKeyException | CertificateException
				| NoSuchAlgorithmException | NoSuchProviderException
				| SignatureException e) {
			fail("Signature Error");
			e.printStackTrace();
		}
		
	}

	@Test
	public void testGenerateCertificateSigningRequest() {
		String subjectName = "CN=Ailtex";
		PKCS10CertificationRequest  request = CertificateOperations.generateCertificateSigningRequest(subjectName, keyPair);
		
		assertEquals("[Test Generate Certificate Request]",subjectName, request.getCertificationRequestInfo().getSubject().toString());
		try {
			assertEquals("[Test Generate Certificate Request]",keyPair.getPublic(), request.getPublicKey());
		} catch (InvalidKeyException | NoSuchAlgorithmException
				| NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	
	}

	@Test
	public void testBuildChain() {
		String subjectName = "CN=Ailtex";
		PKCS10CertificationRequest  request = CertificateOperations.generateCertificateSigningRequest(subjectName, keyPair);
		assertEquals("[Test Build Chain]",subjectName, request.getCertificationRequestInfo().getSubject().toString());
		
		String root = "CN=Bootstrap";
		KeyPair rootKeyPair = null;
		Certificate rootCert = null;
		try {
			rootKeyPair = AsymmetricEncryption.generateKey("RSA", 2048);
			rootCert = CertificateOperations.generateSelfSignedcertificate(root, rootKeyPair, lifeTime);
			Certificate[] certChain = CertificateOperations.buildChain(request, (X509Certificate)rootCert, rootKeyPair, lifeTime);
			
			System.out.println(certChain[0].toString());
			assertEquals("[Test  Build Chain]",keyPair.getPublic(),certChain[0].getPublicKey());
			
		} catch (NoSuchAlgorithmException | InvalidKeyException | CertificateParsingException | 
				NoSuchProviderException | SignatureException e) {
			
			e.printStackTrace();
		}
		
	}

}

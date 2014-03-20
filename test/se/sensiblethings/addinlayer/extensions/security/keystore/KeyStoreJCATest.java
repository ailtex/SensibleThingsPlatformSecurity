package se.sensiblethings.addinlayer.extensions.security.keystore;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.util.Enumeration;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;

import org.junit.Test;

import se.sensiblethings.addinlayer.extensions.security.certificate.CertificateOperations;
import se.sensiblethings.addinlayer.extensions.security.encryption.AsymmetricEncryption;
import se.sensiblethings.addinlayer.extensions.security.encryption.SymmetricEncryption;

public class KeyStoreJCATest {

	private String keyStoreFile = "resouces/KeyStore.db";
	
	@Test
	public void testKeyStoreJCA() {
		try {
			KeyStoreJCA keyStore = new KeyStoreJCA(keyStoreFile,"password".toCharArray());
		} catch (IOException e) {
			e.printStackTrace();
		}
		File file = new File(keyStoreFile);
		assertTrue("[Test Key StroreJCA constructor]", file.exists());
	}

	@Test
	public void testLoadKeyStore() {
		KeyStoreJCA keyStore = new KeyStoreJCA();
		try {
			keyStore.loadKeyStore(keyStoreFile, "password".toCharArray());
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		// ???
		assertNotNull("[Test Load Key Store]", keyStore);
	}

	@Test
	public void testCreateKeyStore() {
		KeyStoreJCA keyStore = new KeyStoreJCA();
		keyStore.createKeyStore(keyStoreFile, "password".toCharArray());
		
		// ???
		assertNotNull("[Test Create KeyStore]", keyStore);
	}

	@Test
	public void testGetPublicKey() {
		String uci = "Bootstrap";
		char[] password = "password".toCharArray();
		
		try {
			KeyStoreJCA keyStore = new KeyStoreJCA(keyStoreFile, password);
					
			KeyPair keyPair = AsymmetricEncryption.generateKey("RSA", 1024);
			Certificate cert = CertificateOperations.generateSelfSignedcertificate("CN=Bootstrap",keyPair, 1*365*24*60*60*1000);
			
			keyStore.storePrivateKey(uci, keyPair.getPrivate(), password, password, new Certificate[]{cert});
				
			assertTrue(keyStore.containAlias(uci));
			
			// convert the public key to Hex format, and then compare them
			assertSame("[Test Get PulicKey]", AsymmetricEncryption.toHexString(keyPair.getPublic().getEncoded()),
					AsymmetricEncryption.toHexString(keyStore.getPublicKey(uci).getEncoded()));
			assertTrue("[Test Get PulicKey]",AsymmetricEncryption.toHexString(keyStore.getPublicKey(uci).getEncoded()).equals(
					AsymmetricEncryption.toHexString(keyPair.getPublic().getEncoded())));

			
		} catch (IOException| KeyStoreException | NoSuchAlgorithmException e) {
			
			e.printStackTrace();
		}
		
	}

	@Test
	public void testGetCertificate() {
		String uci = "Bootstrap-2";
		char[] password = "password".toCharArray();
		
		try {
			KeyStoreJCA keyStore = new KeyStoreJCA(keyStoreFile, password);
			
			KeyPair keyPair = AsymmetricEncryption.generateKey("RSA", 2048);
			Certificate cert = CertificateOperations.generateSelfSignedcertificate("CN=Bootstrap",keyPair, 1*365*24*60*60*1000);
			keyStore.storeCertificate(uci, cert,password);
			
			assertTrue("[Test Get Certificate]",keyStore.getCertificate(uci).equals(cert));
			assertSame("[Test Get Certificate]",cert, keyStore.getCertificate(uci));
			
			CertificateOperations.standOutInPemEncoded((X509Certificate)cert);
			CertificateOperations.standOutInPemEncoded((X509Certificate)keyStore.getCertificate(uci));
			
		} catch (IOException| KeyStoreException | NoSuchAlgorithmException e) {
			
			e.printStackTrace();
		}
	}

	@Test
	public void testGetPrivateKey() {
		String uci = "Bootstrap-3";
		char[] password = "password".toCharArray();
		
		try {
			KeyStoreJCA keyStore = new KeyStoreJCA(keyStoreFile, password);
			
			KeyPair keyPair = AsymmetricEncryption.generateKey("RSA", 1024);
			Certificate cert = CertificateOperations.generateSelfSignedcertificate("CN=Bootstrap",keyPair, 1*365*24*60*60*1000);
			
			keyStore.storePrivateKey(uci, keyPair.getPrivate(), password, password, new Certificate[]{cert});
				
			assertTrue(keyStore.containAlias(uci));
			assertTrue(AsymmetricEncryption.toHexString(keyStore.getPrivateKey(uci, password).getEncoded()).equals(
					AsymmetricEncryption.toHexString(keyPair.getPrivate().getEncoded())));
			
			//System.out.println(keyStore.toString());
			
		} catch (IOException| KeyStoreException | NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Test
	public void testGetSecretKey(){
		String uci = "Bootstrap-4";
		char[] password = "password".toCharArray();
		
		try {
			KeyStoreJCA keyStore = new KeyStoreJCA(keyStoreFile, password);
						
			SecretKey secretKey = SymmetricEncryption.generateKey(SymmetricEncryption.AES, 128);
			keyStore.storeSecretKey(uci, secretKey, password, password);
			
			assertTrue(keyStore.containAlias(uci));
		
			//System.out.println(keyStore.toString());
			
		} catch (IOException| KeyStoreException | NoSuchAlgorithmException | 
				InvalidKeyException | InvalidKeySpecException e) {
			
			e.printStackTrace();
		}
	}

	@Test
	public void testStorePrivateKey() {
		fail("Not yet implemented");
	}

	@Test
	public void testStoreSecretKeyStringByteArrayCharArray() {
		fail("Not yet implemented");
	}

	@Test
	public void testStoreSecretKeyStringSecretKeyCharArray() {
		fail("Not yet implemented");
	}

	@Test
	public void testStoreCertificate() {
		fail("Not yet implemented");
	}

	@Test
	public void testHasKey() {
		fail("Not yet implemented");
	}

	@Test
	public void testHasCertificate() {
		fail("Not yet implemented");
	}

	@Test
	public void testContainAlias() {
		fail("Not yet implemented");
	}

	@Test
	public void testGetCreationData() {
		fail("Not yet implemented");
	}

}

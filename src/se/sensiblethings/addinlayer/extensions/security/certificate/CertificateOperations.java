package se.sensiblethings.addinlayer.extensions.security.certificate;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;

public class CertificateOperations {
	private Certificate cert = null;
	
	
	public CertificateOperations(){
		// add BouncyCastal to the security provider
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}
	
	/**
	 * There is one solution to generate the X509 certificate without using the Bouncy Castle
	 * Detail can be found from below (Actually it's similar to doSelfCert from the keytool souce code):
	 * 1, http://stackoverflow.com/questions/1615871/creating-an-x509-certificate-in-java-without-bouncycastle
	 * 2, http://bfo.com/blog/2011/03/08/odds_and_ends_creating_a_new_x_509_certificate.html
	 * While sun.security.* package is required which has some contradiction with support/ stable principle
	 * So here decide to use Bouncy Castle to implement this
	 * 
	 * @param certificate
	 * @return
	 */
	@SuppressWarnings("deprecation")
	public X509Certificate generateSelfSignedcertificate(KeyPair keyPair){
		X509Certificate cert = null;
		
		X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
		
		certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
		
		// The specification of X.500 distinguished name
		// C Country
		// CN Common name
		// DC Domain component
		// E E-mail address
		// EMAIL E-mail address (preferred)
		// EMAILADDRESS E-mail address
		// L Locality
		// O Organization name
		// OU Organizational unit name
		// PC Postal code
		// S State or province
		// SN Family name
		// SP State or province
		// ST State or province (preferred)
		// STREET Street
		// T Title
		// 
		certGen.setIssuerDN(new X500Principal("CN=Bootstrap,OU=ComputerColleage,O=MIUN,C=Sweden"));
		// set the validation time
	    certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
	    certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
	    
	    certGen.setSubjectDN(new X500Principal("CN=Bootstrap"));
	    certGen.setPublicKey(keyPair.getPublic());
	    certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
	    
	    try {
			cert = certGen.generateX509Certificate(keyPair.getPrivate(), "BC");
		} catch (InvalidKeyException | NoSuchProviderException
				| SecurityException | SignatureException e) {
			
			e.printStackTrace();
		}
	    
	    return cert;
	}
	
	
	public void generateCertificateSigningRequest(){
		
	}
	
	public void signCertificateSigningRequest(){
		
	}
	
	public void signCertificate(Certificate certificate){
		
	}
}

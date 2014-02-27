package se.sensiblethings.addinlayer.extensions.security.certificate;

/*
 * This part is about the certificate operations with Bouncy Castle APIs
 * Here is one document about this part : 
 * http://www.bouncycastle.org/wiki/display/JA1/X.509+Public+Key+Certificate+and+Certification+Request+Generation
 * 
 */

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import org.bouncycastle.openssl.PEMWriter;

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
	public X509Certificate generateSelfSignedcertificate(String subjectName, KeyPair keyPair){
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
		subjectName = "CN=Bootstrap,OU=ComputerColleage,O=MIUN,C=Sweden";
		certGen.setIssuerDN(new X500Principal(subjectName));
		
		// set the validation time
		
	    certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000)); // time from which certificate is valid
	    certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));  // time after which certificate is not valid
	    
	    certGen.setSubjectDN(new X500Principal(subjectName));
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
	
	
	@SuppressWarnings({ "deprecation", "unchecked" })
	public PKCS10CertificationRequest generateCertificateSigningRequest(String subjectName, KeyPair keyPair){
		
		X500Principal sn = new X500Principal(subjectName);
		
		// Creation of the extensionRequest attribute 
		// Including an email address in the SubjectAlternative name extension
		// create the extension value
		GeneralNames subjectAltName = new GeneralNames(
		                   new GeneralName(GeneralName.rfc822Name, "example@example.org"));

		// create the extensions object and add it as an attribute
		Vector oids = new Vector();
		Vector values = new Vector();

		oids.add(X509Extensions.SubjectAlternativeName);
		try {
			values.add(new X509Extension(false, new DEROctetString(subjectAltName)));
		} catch (IOException e1) {
			
			e1.printStackTrace();
		}
		
		// adding extra extensions to the certification request is 
		// just a matter of adding extra oids and extension objects to the oids 
		// and values Vector objects respectively
		
		X509Extensions extensions = new X509Extensions(oids, values);

		Attribute attribute = new Attribute(
		                           PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
		                           new DERSet(extensions));
		
		
		try {
			return new PKCS10CertificationRequest(
			          "SHA256withRSA",
			          sn,
			          keyPair.getPublic(),
			          new DERSet(attribute),    // wrapping it in an ASN.1 SET
			          keyPair.getPrivate());
		} catch (InvalidKeyException | NoSuchAlgorithmException
				| NoSuchProviderException | SignatureException e) {
			
			e.printStackTrace();
		}
		return null;
	}
	
	public void signCertificateSigningRequest(){
		
	}
	
	public void signCertificate(Certificate certificate){
		
	}
	
	public void standOutInPemEncoded(X509Certificate cert){
		PEMWriter pemWrt = new PEMWriter(new OutputStreamWriter(System.out));
		try {
			pemWrt.writeObject(cert);
			pemWrt.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}

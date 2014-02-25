package se.sensiblethings.addinlayer.extensions.security.certificate;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class CertificateOperations {
	private Certificate cert = null;
	
	public X509Certificate generateCertificate(){
		
	}
	
	public void selfSignCertificate(Certificate certificate){
		
	}
	
	public void generateSelfSignedcertificate(Certificate certificate){
		
	}
	
	public X509Certificate generateCertificateSigningRequest(){
		X509Certificate cer;
		
		X509V3CertificateGenerator cert = new X509V3CertificateGenerator();   
	   	cert.setSerialNumber(BigInteger.valueOf(1));   //or generate a random number  
	   	cert.setSubjectDN(new X509Principal("CN=localhost"));  //see examples to add O,OU etc  
	   	cert.setIssuerDN(new X509Principal("CN=localhost")); //same since it is self-signed  
		cert.setPublicKey(keyPair.getPublic());  
		cert.setNotBefore(<date>);  
		cert.setNotAfter(<date>);  
		cert.setSignatureAlgorithm("SHA1WithRSAEncryption");   
		PrivateKey signingKey = keyPair.getPrivate();
		
	    return cert.generate(signingKey, "BC"); 
	}
	
	public void signCertificateSigningRequest(){
		
	}
}

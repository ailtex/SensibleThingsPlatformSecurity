package se.sensiblethings.addinlayer.extensions.security.parameters;

public enum SecurityLevel {
	// The high security level parameters
	// Level: 5
	// Symmetric Encryption Algorithm: AES,
	// Symmetric Mode : CBC Mode, and PKCS5Padding method
	// Symmetric key length : 256
	// Symmetric key lifetime : 5 min = 5*60*1000 ms
	// Asymmetric Encryption Algorthm: RSA
	// Asymmetric key length: 2048
	// Signature algorithm: SHA512 with RSA
	// Asymmetric Key lifetime : 365*24*60*60*1000;
	High(5, "AES","AES/CBC/PKCS5Padding", 256, 5*60*1000L, "RSA", 2048, "SHA512withRSA", 365*24*60*60*1000),
	Medium(3, "AES","AES/CBC/PKCS5Padding", 192, 60*60*1000L, "RSA", 2048, "SHA256withRSA", 365*24*60*60*1000),
	Low(1, "AES", "AES/CBC/PKCS5Padding", 128, 24*60*60*1000L, "RSA", 1024, "SHA1withRSA", 365*24*60*60*1000);
	
	private int securityLevel;
	
	private String symmetricAlgorithm;
	private String symmetricMode;
	private int symmetricKeyLength;
	private long symmetricKeyLifeTime;
	
	private String asymmetricAlgorithm;
	private int asymmetricKeyLength;
	
	private String signatureAlgorithm;
	private long asymmetricKeyLifetime;
	
	private SecurityLevel(int securityLevel, String symmetricAlgorithm, String symmetricMode,
			int symmetricKeyLength, long symmetricKeyLifeTime,
			String asymmetricAlgorithm, int asymmetricKeyLength,
			String signatureAlgorithm, long asymmetricKeyLifetime) {
		this.securityLevel = securityLevel;
		this.symmetricAlgorithm = symmetricAlgorithm;
		this.symmetricMode = symmetricMode;
		this.symmetricKeyLength = symmetricKeyLength;
		this.symmetricKeyLifeTime = symmetricKeyLifeTime;
		this.asymmetricAlgorithm = asymmetricAlgorithm;
		this.asymmetricKeyLength = asymmetricKeyLength;
		this.signatureAlgorithm = signatureAlgorithm;
		this.asymmetricKeyLifetime = asymmetricKeyLifetime;
	}

	public int getSecurityLevel() {
		return securityLevel;
	}

	public String getSymmetricAlgorithm() {
		return symmetricAlgorithm;
	}

	public String getSymmetricMode(){
		return symmetricMode;
	}

	public int getSymmetricKeyLength() {
		return symmetricKeyLength;
	}



	public long getSymmetricKeyLifeTime() {
		return symmetricKeyLifeTime;
	}



	public String getAsymmetricAlgorithm() {
		return asymmetricAlgorithm;
	}



	public int getAsymmetricKeyLength() {
		return asymmetricKeyLength;
	}



	public String getSignatureAlgorithm() {
		return signatureAlgorithm;
	}

	public long getAsymmetricKeyLifetime() {
		return asymmetricKeyLifetime;
	}

	public void setAsymmetricKeyLifetime(long asymmetricKeyLifetime) {
		this.asymmetricKeyLifetime = asymmetricKeyLifetime;
	}

	
}

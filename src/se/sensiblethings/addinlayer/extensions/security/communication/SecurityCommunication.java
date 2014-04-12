package se.sensiblethings.addinlayer.extensions.security.communication;

import java.nio.ByteBuffer;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Random;
import java.util.Vector;

import javax.crypto.SecretKey;

import org.apache.commons.lang.SerializationUtils;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;

import se.sensiblethings.addinlayer.extensions.security.SecurityManager;
import se.sensiblethings.addinlayer.extensions.security.communication.message.CertificateAcceptedResponseMessage;
import se.sensiblethings.addinlayer.extensions.security.communication.message.CertificateExchangeMessage;
import se.sensiblethings.addinlayer.extensions.security.communication.message.CertificateExchangeResponseMessage;
import se.sensiblethings.addinlayer.extensions.security.communication.message.CertificateRequestMessage;
import se.sensiblethings.addinlayer.extensions.security.communication.message.CertificateResponseMessage;
import se.sensiblethings.addinlayer.extensions.security.communication.message.RegistrationRequestMessage;
import se.sensiblethings.addinlayer.extensions.security.communication.message.RegistrationResponseMessage;
import se.sensiblethings.addinlayer.extensions.security.communication.message.SessionKeyExchangeMessage;
import se.sensiblethings.addinlayer.extensions.security.communication.message.SessionKeyResponseMessage;
import se.sensiblethings.addinlayer.extensions.security.communication.message.CommunicationShiftMessage;
import se.sensiblethings.addinlayer.extensions.security.communication.payload.CertificateExchangePayload;
import se.sensiblethings.addinlayer.extensions.security.communication.payload.CertificatePayload;
import se.sensiblethings.addinlayer.extensions.security.communication.payload.CertificateRequestPayload;
import se.sensiblethings.addinlayer.extensions.security.communication.payload.CertificateResponsePayload;
import se.sensiblethings.addinlayer.extensions.security.communication.payload.RegistrationPayload;
import se.sensiblethings.addinlayer.extensions.security.communication.payload.SecretKeyPayload;
import se.sensiblethings.addinlayer.extensions.security.configuration.SecurityConfiguration;
import se.sensiblethings.addinlayer.extensions.security.encryption.AsymmetricEncryption;
import se.sensiblethings.addinlayer.extensions.security.encryption.SymmetricEncryption;
import se.sensiblethings.addinlayer.extensions.security.signature.SignatureOperations;
import se.sensiblethings.disseminationlayer.communication.Communication;
import se.sensiblethings.disseminationlayer.communication.DestinationNotReachableException;
import se.sensiblethings.disseminationlayer.communication.Message;
import se.sensiblethings.disseminationlayer.communication.rudp.RUDPCommunication;
import se.sensiblethings.disseminationlayer.communication.ssl.SslCommunication;
import se.sensiblethings.disseminationlayer.disseminationcore.DisseminationCore;
import se.sensiblethings.interfacelayer.SensibleThingsNode;
import se.sensiblethings.interfacelayer.SensibleThingsPlatform;

public class SecurityCommunication {
	SensibleThingsPlatform platform = null;
	DisseminationCore core = null;
	Communication communication = null;
	
	SecurityManager securityManager = null;
	SecurityConfiguration config = null;
	
	Map<String, Vector<SecureMessage>> postOffice = null;
	
	public SecurityCommunication(SensibleThingsPlatform platform, 
			SecurityManager securityManager, SecurityConfiguration config){
		this.platform = platform;
		this.core = platform.getDisseminationCore();
		this.communication = core.getCommunication();
		
		this.securityManager = securityManager;
		this.config = config;
		
		postOffice = new HashMap<String, Vector<SecureMessage>>();
	}
	
	public void setSecuiryConfiguraton(SecurityConfiguration config){
		this.config = config;
	}
	
	
	/**
	 * Create a SSL connection with bootstrap node
	 * 
	 * (1.1) C->B: Create a SSL Session with B
	 * 
	 * @param uci the uci who own the bootstrap node
	 * @param node the node that SSL connection is established with 
	 */
	public void createSslConnection(String uci, SensibleThingsNode node){
		//Send out the SslConnectionRequestMessage Message
		CommunicationShiftMessage message = new CommunicationShiftMessage(uci, securityManager.getMyUci(), 
				node, communication.getLocalSensibleThingsNode());
		
		message.setSignal("SSL");
		// this message may not be secure, as if some one can hijack it
	    // if the bootstrap node can set up several different communications simultaneously
	    // the request node can just change itself communication type
		
		sendMessage(message);
		/*
		try {
			Thread.sleep(100);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		*/
		
		transformCommunication("SSL");
		
	}
	
	public void handleCommunicationShiftMessage(CommunicationShiftMessage csm) {
		if(csm.getSignal() != null){
			transformCommunication(csm.getSignal());
		}
	
	}
	
	/**
	 * register the self uci to bootstrap node
	 *  
	 * (1.2) C->B: IDC || Request || TS1
	 *  
	 * @param toUci the boostrap's uci
	 * @param node the bootstrap node
	 * @param fromUci itself uci that will be registered
	 */
	public void register(String toUci, SensibleThingsNode node){
//		System.out.println("[Register] " + securityManager.getMyUci() + " --> " + toUci);
		
		RegistrationRequestMessage message = new RegistrationRequestMessage(toUci, securityManager.getMyUci(), 
				node, communication.getLocalSensibleThingsNode());
		
		// set the payload
		RegistrationPayload payload = new RegistrationPayload(securityManager.getMyUci(), toUci);
		payload.setTimeStamp(System.currentTimeMillis());
		byte[] payloadInBytes= SerializationUtils.serialize(payload);
				
		message.setPayload(payloadInBytes);
		message.setSignature(null);
		
		// store the local registration Request Time
		securityManager.addToNoncePool("RegistrationRequest", payloadInBytes);

		sendMessage(message);
	}
	
	/**
	 * Handle Registration Request Message, sends back an registration response message
	 * 
	 * (1.3) B->C: IDB || PUB || E(PRB, [IDC || Request || TS1])
	 * 
	 * @param rrm
	 */
	public void handleRegistrationRequestMessage(
			RegistrationRequestMessage rrm) {
		
//		System.out.println("[Handle Registration Request Message] " + " from "+ rrm.fromUci);
		
		RegistrationResponseMessage registrationResponseMessage = 
				new RegistrationResponseMessage(rrm.fromUci, securityManager.getMyUci(), 
						rrm.getFromNode(),communication.getLocalSensibleThingsNode());
				
		// set the Root certificate from Bootstrap and send it to the applicant
		registrationResponseMessage.setCertificate(securityManager.getCertificate());
		
		// set the signature algorithm of the message
		registrationResponseMessage.setSignatureAlgorithm(config.getSignatureAlgorithm());
		
		// signed the request message
		byte[] signature = securityManager.signMessage(rrm.getPayload(), config.getSignatureAlgorithm());
		
		// set the signature
		registrationResponseMessage.setSignature(signature);
		
		// send out the message
		sendMessage(registrationResponseMessage);
	}
	
	/**
	 * Handle Registration Response Message
	 * 
	 * (1.4) C->B: E(PUB, [IDC || N1 ]) || CERTc (IDC || PUC || E(PRC, H(IDC || PUC)) ) 
	 * 
	 * @param rrm
	 */
	public void handleRegistrationResponseMessage(
			RegistrationResponseMessage rrm) {
//		System.out.println("[Handle Registration Response Message ]" + " from " + rrm.fromUci);
		
	  	// verify the signature with the given certificate from bootstrap
		if(securityManager.verifySignature((byte[])securityManager.getFromNoncePool("RegistrationRequest"), 
				rrm.getSignature(), rrm.getCertificate(), rrm.getSignatureAlgorithm())){
			
			// remove the registration request from the nonce pool
			securityManager.removeFromNoncePool("RegistrationRequest");
			
			// store the bootstrap's root certificate(X509V1 version)
			securityManager.storeCertificate(rrm.fromUci, rrm.getCertificate(), "password");
			
			// the request is valid
			// send the certificate request message with ID, CSR, nonce 
			CertificateRequestMessage crm = 
					new CertificateRequestMessage(config.getBootstrapUci(),
							securityManager.getMyUci(), rrm.getFromNode(), communication.getLocalSensibleThingsNode());
			
			//generate an certificate signing request
			PKCS10CertificationRequest certRequest = 
					securityManager.getCertificateSigingRequest(securityManager.getMyUci());
			
			crm.setCertRequest(certRequest);
			
			// set the nonce
			int nonce = new Random().nextInt();
			crm.setNonce(securityManager.asymmetricEncryptMessage(
					rrm.fromUci, String.valueOf(nonce).getBytes(), config.getAsymmetricAlgorithm()));
			
			// store the nonce into the data pool, corresponding the bootstrap's uci
			securityManager.addToNoncePool(rrm.fromUci, nonce);
			
			
			// set the fromUci
			crm.setUci(securityManager.asymmetricEncryptMessage(
					rrm.fromUci, securityManager.getMyUci().getBytes(), config.getAsymmetricAlgorithm()));
			
			
//			CertificateRequestPayload payload = 
//					new CertificateRequestPayload(securityManager.getMyUci(), rrm.fromUci);
			
//			payload.setNonce(nonce);
			
//			// use apache.commons.lang.SerializationUtils to serialize objects
//			byte[] plainText = SerializationUtils.serialize(payload);
//			
//			
//			// encrypt message
//			byte[] cipherText = securityManager.asymmetricEncryptMessage(rrm.fromUci, plainText, config.getAsymmetricAlgorithm());
//			
//			// set the encrypted payload
//			crm.setPayload(cipherText);
//			
			sendMessage(crm);
			
		}else{
			System.out.println("[Error] Fake signature");
		}
	}

	/**
	 * Handle Certificate Request Message
	 * 
	 * (1.5) B->C: E(PUC, K ) || E(K, [Certification || N1 || N2])
	 * 
	 * @param crm
	 */
	public void handleCertificateRequestMessage(CertificateRequestMessage crm) {
//		System.out.println("[Handle Certificate Request Message ]" + " from " + crm.fromUci);
		
//		byte[] cipherText = crm.getPayload();
		
		// decrypt the payload
//		byte[] plainText = securityManager.asymmetricDecryptMessage(cipherText, 
//				config.getAsymmetricAlgorithm());
//		
//		// deserialize the payload
//		CertificateRequestPayload payload = (CertificateRequestPayload)SerializationUtils.deserialize(plainText);
//		
		// Get the certificate signing request
		PKCS10CertificationRequest certRequest = crm.getCertRequest();
		
		
		// Get the uci
		String uci = new String(securityManager.asymmetricDecryptMessage(crm.getUci(), config.getAsymmetricAlgorithm()));
		
		// Get the nonce
		int nonce = Integer.valueOf(new String(securityManager.asymmetricDecryptMessage(crm.getNonce(), config.getAsymmetricAlgorithm()))) ;
		
		// varify the certificate signing request
		if(securityManager.isCeritificateSigningRequestValid(certRequest, uci)){
			Certificate[] certs = (Certificate[]) securityManager.signCertificateSigningRequest(certRequest, crm.fromUci);
			
			
			// generate the session key and  store it locally
			securityManager.generateSymmetricSecurityKey(crm.fromUci, config.getSymmetricAlgorithm(), config.getSymmetricKeyLength());
			
			CertificateResponseMessage certRespMesg = new CertificateResponseMessage(crm.fromUci, securityManager.getMyUci(),
															crm.getFromNode(), communication.getLocalSensibleThingsNode());
			
			certRespMesg.setEncryptSecretKey(securityManager.asymmetricEncryptMessage(
								crm.fromUci, 
								securityManager.getSecretKey(crm.fromUci, "password".toCharArray()).getEncoded(),
								config.getAsymmetricAlgorithm()));
			
			CertificateResponsePayload responsePayload = 
					new CertificateResponsePayload(securityManager.getMyUci(), crm.fromUci);
			
			// set the nonces
			responsePayload.setToNonce(nonce);
			
			int fromNonce = new Random().nextInt();
			responsePayload.setFromNonce(fromNonce);
			// store into the data pool
			securityManager.addToNoncePool(crm.fromUci, fromNonce);
			
			// set the certificate chain, which contains the signed certificate and root certificate of Bootstrap
			responsePayload.setCertChain(certs);
			
			byte[] encryptPayload = securityManager.symmetricEncryptMessage(crm.fromUci, 
					SerializationUtils.serialize(responsePayload), config.getSymmetricMode());
			
			byte[] iv = securityManager.getIVparameter();
			if(iv != null){
				certRespMesg.setIv(securityManager.symmetricEncryptIVParameter(crm.fromUci, iv));
			}
			
			certRespMesg.setPayload(encryptPayload);
			
			sendMessage(certRespMesg);
			
		}else{
			System.out.println("[Handle Certificate Request Message] " + "Ceritificate Signing Request Error");
		}
		
	}
	
	/**
	 * Handle Certificate Response Message
	 * 
	 * (1.6) C->B : E(K, N2)
	 * 
	 * @param crm
	 */
	public void handleCertificateResponseMessage(
			CertificateResponseMessage crm) {
//		System.out.println("[Handle Certificate Response Message ]" + " from " + crm.fromUci + " to " + crm.toUci);
		
		byte[] encryptSecretKey = crm.getEncryptSecretKey();
		// decrypt the secret key
		byte[] secretKey = securityManager.asymmetricDecryptMessage(encryptSecretKey, 
				config.getAsymmetricAlgorithm());
		
		// decrypt the iv
		byte[] iv = null;
		byte[] payload = null;
		if(crm.getIv() != null){
			iv = securityManager.symmetricDecryptIVparameter(secretKey, crm.getIv());
			// decrypt the certificates and nonces
			payload = securityManager.symmetricDecryptMessage(secretKey, crm.getPayload(), iv, 
					config.getSymmetricMode());
		}else{
			payload = securityManager.symmetricDecryptMessage(secretKey, crm.getPayload(), 
					config.getSymmetricMode());
		}

		// deserialize
		CertificateResponsePayload responsePayload = (CertificateResponsePayload)
				SerializationUtils.deserialize(payload);
		
		// varify the nonce
		if(responsePayload.getToNonce() == (Integer)securityManager.getFromNoncePool(crm.fromUci)){
			// remove the nonce from the data pool
			securityManager.removeFromNoncePool(crm.fromUci);
			
			// store the secret key
			securityManager.storeSecretKey(crm.fromUci, secretKey, config.getSymmetricAlgorithm(), "password");
			
			securityManager.storeCertificateChain(securityManager.getMyUci(), responsePayload.getCertChain(), "password");
			
			//send back CertificateAcceptedResponseMessage
			CertificateAcceptedResponseMessage carm = 
					new CertificateAcceptedResponseMessage(crm.fromUci, securityManager.getMyUci(), 
							crm.getFromNode(), communication.getLocalSensibleThingsNode());
			
			int nonce =  responsePayload.getFromNonce();
			
			carm.setPayload(securityManager.symmetricEncryptMessage(crm.fromUci, 
					String.valueOf(nonce).getBytes(), config.getSymmetricMode()));
			
			byte[] ivParameter = securityManager.getIVparameter();
			if(ivParameter != null){
				carm.setIv(securityManager.symmetricEncryptIVParameter(crm.fromUci, ivParameter));
			}
			
			sendMessage(carm);
			
			// send the communication shift message 
			CommunicationShiftMessage csm = new CommunicationShiftMessage(crm.fromUci, securityManager.getMyUci(), 
					crm.getFromNode(), communication.getLocalSensibleThingsNode());
			csm.setSignal("RUDP");
			
			sendMessage(csm);
			
			transformCommunication(csm.getSignal());
			
			System.out.println("Registration finished!");
			
		}else{
			System.out.println("[Hanle Certificate Response Message] Wrong Nonce !");
		}
	}
	
	public void handleCertificateAcceptedResponseMessage(
			CertificateAcceptedResponseMessage carm) {
		
//		System.out.println("[Handle Certificate Accepted Response Message ]" + " from " + carm.fromUci);
		byte[] iv = null;
		byte[] payload = null;
		if(carm.getIv() != null){
			iv = securityManager.symmetricDecryptIVparameter(carm.fromUci, carm.getIv());
			payload = securityManager.symmetricDecryptMessage(
					carm.fromUci, carm.getPayload(), iv, config.getSymmetricMode());
		}else{
			payload = securityManager.symmetricDecryptMessage(
					carm.fromUci, carm.getPayload(), config.getSymmetricMode());
		}
		
		// convert byte array to integer
		int nonce = Integer.valueOf(new String(payload));
		
		if(nonce == (Integer)securityManager.getFromNoncePool(carm.fromUci)){
			System.out.println("[Handle Certificate Accepted Response Message] Certificate has been safely transmitted!");
			
			// remove the nonce from the data pool
			securityManager.removeFromNoncePool(carm.fromUci);
		}else{
			System.out.println("[Handle Certificate Accepted Response Message] Error!");
		}
		
	}
	
	
	/**
	 * Send encrypt message
	 * 
	 * (2.1) if (IDD, KS, Lifetime) exist, and Lifetime is valid
	 *       C->D: E(KS, IDC || M || E(PRC, [H(M)] ) )
	 * 
	 * @param message
	 * @param toUci
	 * @param toNode
	 */
	public void sendSecureMassage(String message, String toUci, SensibleThingsNode toNode){   
		
		// create the secureMessage without encrypting the message
		SecureMessage secureMessage = new SecureMessage(toUci, securityManager.getMyUci(), 
				toNode, communication.getLocalSensibleThingsNode());
		
		secureMessage.setPayload(message.getBytes());
				
		if(securityManager.isSymmetricKeyValid(toUci, config.getSymmetricKeyLifeTime())){
			sendToPostOffice(secureMessage);
			securityManager.encapsulateSecueMessage(postOffice, toUci);
			sendOutSecureMessage(toUci);
			
		}else if(securityManager.hasCertificate(toUci)){
			exchangeSessionKey(toUci, toNode);			
			sendToPostOffice(secureMessage);
		}else{
			exchangeCertificate(toUci, toNode);
			sendToPostOffice(secureMessage);	
		}
	}
	
	public String handleSecureMessage(SecureMessage sm){
		byte[] signature = sm.getSignature();
		String plainText = securityManager.decapsulateSecureMessage(sm);
		if(securityManager.verifySignature(plainText.getBytes(), signature, sm.fromUci, config.getSignatureAlgorithm())){
			return plainText;
		}else{
			return null;
		}
				
	}

	/**
	 * Exchange Session Key
	 * (2.2) If (IDD, KS, Lifetime) temporary key store doesn’t exist, or Lifetime is invalid
	 *       C->D : E(PUD, KS) || E(PRC, H ([KS])) || E(KS, IDC || N1) || CertificateC
	 *              
	 * @param toUci
	 * @param toNode
	 */
	private void exchangeSessionKey(String toUci, SensibleThingsNode toNode) {
		
		SessionKeyExchangeMessage skxm = new SessionKeyExchangeMessage(toUci, securityManager.getMyUci(),
				toNode, communication.getLocalSensibleThingsNode());
		
		// generate the symmetric security key
		securityManager.generateSymmetricSecurityKey(toUci, config.getSymmetricAlgorithm(), config.getSymmetricKeyLength());
		
		// set the payload
		byte[] secretKey = securityManager.getSecretKey(toUci, "password".toCharArray()).getEncoded();
		skxm.setPayload(securityManager.asymmetricEncryptMessage(toUci, secretKey, config.getAsymmetricAlgorithm()));
		skxm.setSignature(securityManager.signMessage(secretKey, config.getSignatureAlgorithm()));
		skxm.setSignatureAlgorithm(config.getSignatureAlgorithm());
		
		// set the secret key payload
		SecretKeyPayload secretKeyPayload = new SecretKeyPayload(securityManager.getMyUci(), toUci);
		
		// set nonce and add it to the data pool
		int nonce = new Random().nextInt();
		secretKeyPayload.setNonce(nonce);
		securityManager.addToNoncePool(toUci, nonce);
		
		byte[] payload = SerializationUtils.serialize(secretKeyPayload);
		skxm.setSecretKeyPayload(securityManager.symmetricEncryptMessage(toUci, payload, config.getSymmetricMode()));
		
		// set the iv, only for AES
		byte[] iv = securityManager.getIVparameter();
		if(iv != null){
			skxm.setIv(securityManager.symmetricEncryptIVParameter(toUci, iv));
		}
		
		// set the certificatePayload
		CertificatePayload certPayload = new CertificatePayload(securityManager.getMyUci(), toUci);
		certPayload.setCert(securityManager.getCertificate());
		
		byte[] certificatePayload = SerializationUtils.serialize(certPayload);
		
		skxm.setCertificatePayload(certificatePayload);		
		
		sendMessage(skxm);
		
	}
	
	/**
	 * Handle session key exchange message, sending back session key response message
	 * 
	 * (2.3) D: store (IDC, KS, Lifetime) in temporary key store
	 *       D->C : E(KS, payload) || E(PRD, H(payload))
	 *       payload = IDD || IDC || N1 || N2
	 * 
	 * @param skxm
	 */
	public void handleSessionKeyExchangeMessage(SessionKeyExchangeMessage skxm) {
		// 1, check the source id
		// 2, check if the ID exist
		// 3, check if the certificate valid
		// 4, decrypt the session key and check its signature
		
		// Get the certificate
		
		boolean isValid = false;
		
		// if it contacted before, it jump checking the certificate 
		if(securityManager.isContactedBefore(skxm.fromUci)){
			isValid = true;
		}else{
			CertificatePayload certPayload = (CertificatePayload)SerializationUtils.deserialize(skxm.getCertificatePayload());
			
			System.out.println("[Handle session key exchange message] " + certPayload.getCert());
			
			if(securityManager.isCertificateValid(certPayload.getCert(), skxm.fromUci)){
				isValid = true;
				securityManager.storeCertificate(skxm.fromUci, certPayload.getCert(), "password");
			}
		}
		
		if(isValid){
			// Decapsulate the secret key
			byte[] secretKey = 
					securityManager.asymmetricDecryptMessage(skxm.getPayload(), config.getAsymmetricAlgorithm());
			
			// check the payload signature
			if(!securityManager.verifySignature(secretKey, skxm.getSignature(),
					securityManager.getPublicKey(skxm.fromUci), skxm.getSignatureAlgorithm())){
				System.out.println("[Handle Session Key Exchange Message] Signature Error");
				return;
			}
			
			byte[] iv = null;
			byte[] payload = null;
			
			// if RC4 not used
			if(skxm.getIv() != null){
				iv = securityManager.symmetricDecryptIVparameter(secretKey, skxm.getIv());
				payload = securityManager.symmetricDecryptMessage(secretKey, 
						skxm.getSecretKeyPayload(),iv, config.getSymmetricMode());
			}else{
				payload = securityManager.symmetricDecryptMessage(secretKey, 
						skxm.getSecretKeyPayload(),config.getSymmetricMode());
			}
			
			SecretKeyPayload secretKeyPayload = (SecretKeyPayload) SerializationUtils.deserialize(payload);
			
			// check the id
			if(!secretKeyPayload.getFromUci().equals(skxm.fromUci)){
				System.out.println("[Handle Session Key Exchange Message] ID Error");
				return;
			}
				
			// store the session key
			securityManager.storeSecretKey(skxm.fromUci, secretKey, config.getSymmetricAlgorithm(),  "Password");

			
			
			// send back an response message
			SessionKeyResponseMessage responseMessage = new SessionKeyResponseMessage(skxm.fromUci,
					securityManager.getMyUci(), skxm.getFromNode(),
					communication.getLocalSensibleThingsNode());

			ResponsePayload responsePayload = new ResponsePayload(skxm.fromUci, securityManager.getMyUci());

			// set the nonce
			int nonce = new Random().nextInt();
			// set to nonce
			responsePayload.setToNonce(secretKeyPayload.getNonce());
			// set from nonce
			responsePayload.setFromNonce(nonce);
			// add the fromNonce to the data pool
			securityManager.addToNoncePool(skxm.fromUci, nonce);

			byte[] responsePayloadInByte = SerializationUtils.serialize(responsePayload);
			
			responseMessage.setSignature(securityManager.signMessage(responsePayloadInByte, 
					config.getSignatureAlgorithm()));

			responseMessage.setPayload(securityManager.symmetricEncryptMessage(
							skxm.fromUci, responsePayloadInByte,
							config.getSymmetricAlgorithm()));
			
			// set the iv parameter
			byte[] ivParameter =  securityManager.getIVparameter();
			if(ivParameter != null){
				responseMessage.setIv(securityManager.symmetricEncryptIVParameter(skxm.fromUci, ivParameter));
			}
			
			sendMessage(responseMessage);
		}
	}
	
	/**
	 * Handle session key response message
	 * 
	 * (2.4) C->D : E(KS, M || N2 || E(PRC, H(M)))
	 * 
	 * @param skrm
	 */
	public void handleSessionKeyResponseMessage(SessionKeyResponseMessage skrm) {
		
		byte[] iv = null;
		byte[] payload = null;
		if(skrm.getIv() != null){
			iv = securityManager.symmetricDecryptIVparameter(skrm.fromUci, skrm.getIv());
			payload = securityManager.symmetricDecryptMessage(skrm.fromUci, skrm.getPayload(), iv,
					config.getSymmetricAlgorithm());
		}else{
			payload = securityManager.symmetricDecryptMessage(skrm.fromUci, skrm.getPayload(),
					config.getSymmetricAlgorithm());
		}

		
		// verify the signature
		if(securityManager.verifySignature(payload, skrm.getSignature(), skrm.fromUci, skrm.getSignatureAlgorithm())){
			
			ResponsePayload responsePayload = (ResponsePayload)SerializationUtils.deserialize(payload);
			if(responsePayload.getToNonce() == (Integer)securityManager.getFromNoncePool(skrm.fromUci)){
				securityManager.removeFromNoncePool("nonce");
				
				// encrypt the message
				securityManager.encapsulateSecueMessage(postOffice, skrm.fromUci);
				sendOutSecureMessage(skrm.fromUci);
			}
		}else{
			System.out.println("[Handle session key response message] Signature Error");
		}
		
	}
	
	/**
	 * If (IDD, PUD, Validation) doesn’t exist or invalid, Exchange certificate
	 * 
	 * (3.1) C->D : Payload || E(PRC,[H(payload)])
	 *            Payload = IDC || CertificateC || TS1 
	 * 
	 * @param toUci
	 * @param toNode
	 */
	private void exchangeCertificate(String toUci, SensibleThingsNode toNode) {
		CertificateExchangeMessage cxm = new CertificateExchangeMessage(toUci, securityManager.getMyUci(),
				toNode, communication.getLocalSensibleThingsNode());
		
		CertificateExchangePayload cxp = new CertificateExchangePayload(securityManager.getMyUci(), toUci);
		cxp.setCert(securityManager.getCertificate());
		cxp.setTimeStamp(System.currentTimeMillis());
		
		byte[] payload = SerializationUtils.serialize(cxp);
		cxm.setPayload(payload);
		cxm.setSignature(securityManager.signMessage(payload, config.getSignatureAlgorithm()));
		cxm.setSignatureAlgorithm(config.getSignatureAlgorithm());
		
		sendMessage(cxm);
	}
	
	
	/**
	 * Handle Certificate Exchange Message
	 * 
	 * (3.2) D : verify the CertificateC
	 *    
	 *     D->C : E(PUC, Payload) || E(PRC, H(Payload))
	 *            Payload = IDD || CertificateD || TS1 
	 * @param cxm
	 */
	public void handleCertificateExchangeMessage(CertificateExchangeMessage cxm) {
		//Decapsulte the Certificate
		byte[] payload = cxm.getPayload();
		CertificateExchangePayload cxp = (CertificateExchangePayload)SerializationUtils.deserialize(payload);
		Certificate cert = cxp.getCert();
		
		// check signature
		if(!securityManager.verifySignature(cxm.getPayload(), cxm.getSignature(), cert, cxm.getSignatureAlgorithm())){
			System.out.println("[Handle Certificate Exchange Message] Signature Error!");
			return;
		}
		
		
		// verify the certificate
		if (securityManager.isCertificateValid(cert, cxm.fromUci)) {
			// store the certificate
			securityManager.storeCertificate(cxm.fromUci, cert, "password");
			
			// send back response message
			CertificateExchangeResponseMessage cxrm = new CertificateExchangeResponseMessage(cxm.fromUci,
					securityManager.getMyUci(), cxm.getFromNode(), communication.getLocalSensibleThingsNode());
			
			// reuse the CertificateExchangePayload
			cxp.setFromUci(securityManager.getMyUci());
			cxp.setToUci(cxm.fromUci);
			cxp.setCert(securityManager.getCertificate());
			
			byte[] cxrmPayload = SerializationUtils.serialize(cxp);
			
//			System.out.println("[Handle Certificate Exchange Message] payload size: " + cxrmPayload.length );
			
			// set the payload
			cxrm.setPayload(securityManager.asymmetricEncryptMessage(cxm.fromUci, cxrmPayload, config.getAsymmetricAlgorithm()));
			// set the signature
			cxrm.setSignature(securityManager.signMessage(cxrmPayload, cxm.getSignatureAlgorithm()));
			
			// send
			sendMessage(cxrm);
		}
		
	}
	
	/**
	 * Handle Certificate Exchange Response Message
	 * 
	 * (3.3) C : verify the CertificateD
	 *       C->D : E(PUD, E(PRC, [KS || Lifetime])) || E(KS, [IDC || N1])
	 * @param cxrm
	 */
	public void handleCertificateExchangeResponseMessage(
			CertificateExchangeResponseMessage cxrm) {
		//Decapsulte the Certificate
		byte[] encryptPayload = cxrm.getPayload();
		byte[] payload = securityManager.asymmetricDecryptMessage(encryptPayload, config.getAsymmetricAlgorithm());
		
		CertificateExchangePayload cxp = (CertificateExchangePayload)SerializationUtils.deserialize(payload);
		Certificate cert = cxp.getCert();
		
		// check signature
		if(!securityManager.verifySignature(payload, cxrm.getSignature(), cert, cxrm.getSignatureAlgorithm())){
			System.out.println("[Handle Certificate Exchange Response Message] Signature Error!");
			return;
		}
		
		// check the source ID and 
		if(!cxp.getFromUci().equals(cxrm.fromUci) || !cxp.getToUci().equals(cxrm.toUci)){
			System.out.println("[Handle Certificate Exchange Response Message] ID Error!");
			return;
		}
		
		// verify the certificate
		if (securityManager.isCertificateValid(cert, cxrm.fromUci)) {
			// store the certificate
			securityManager.storeCertificate(cxrm.fromUci, cert, "password");
			
			exchangeSessionKey(cxrm.toUci, cxrm.getFromNode());
		}
	}
	


	private void sendToPostOffice(SecureMessage sm){
		String toUci = sm.toUci;
		if(postOffice.containsKey(toUci)){
			postOffice.get(toUci).add(sm);
		}else{
			postOffice.put(toUci, new Vector<SecureMessage>());
			postOffice.get(toUci).add(sm);
		}
	}
	
	private void sendOutSecureMessage(String toUci) {
		if(postOffice.containsKey(toUci)){
			Iterator<SecureMessage> it = postOffice.get(toUci).iterator();
			while(it.hasNext()){
				sendMessage(it.next());
				
				// let the sender wait every 20ms 
//				try {
//					Thread.sleep(20);
//				} catch (InterruptedException e) {
//					e.printStackTrace();
//				}
			}
			postOffice.get(toUci).removeAllElements();
		}
	}
	
	private void transformCommunication(String communicationType){
		System.out.println("[" + securityManager.getMyUci() + 
				" : Communication] communication type shift from "+ communication +  " to "+ communicationType + " mode");
		
		try {
			Thread.sleep(1000);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		Communication origin = communication;
		
		if(communicationType.equals("SSL")){
			
			SslCommunication.initCommunicationPort = communication.getLocalSensibleThingsNode().getPort();
			
			Class<?> communicationLoader;
			try {
				communicationLoader = Class.forName(Communication.SSL);
				communication = (Communication) communicationLoader.newInstance();
			} catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			
			communication.setMessageListeners(origin.getMessageListeners()); 
			
			
//			if(platform.isBehindNat()){
//				System.out.println("[System] Proxy SSL");
//				platform.changeCommunicationTo(communication.PROXY_SSL);
//			}else{
//				// SslCommunication.initCommunicationPort = 9009;
//				platform.changeCommunicationTo(communication.SSL);
//			}
			
			origin.shutdown();
			System.out.println("[Communication] shutdown !");
			
		}else if(communicationType.equals("RUDP")){
			RUDPCommunication.initCommunicationPort = communication.getLocalSensibleThingsNode().getPort();
			
			Class<?> communicationLoader;
			try {
				communicationLoader = Class.forName(Communication.RUDP);
				communication = (Communication) communicationLoader.newInstance();
			} catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			communication.setMessageListeners(origin.getMessageListeners()); 
			
//			if(platform.isBehindNat()){
//				platform.changeCommunicationTo(communication.PROXY_RUDP);
//			}else{
//				platform.changeCommunicationTo(communication.RUDP);
//			}
		}
		
		// reset the communication in lookup service
		core.getLookupService().setCommunication(communication);
		
//		System.out.println("[" + securityManager.getMyUci() + 
//				" : Communication] port = " + communication.getLocalSensibleThingsNode().getPort());
		System.out.println("[" + securityManager.getMyUci() + 
				" : Communication] communication shift to " + communication );
	}
	
	
	private void sendMessage(Message message){
		try {
			communication.sendMessage(message);
		} catch (DestinationNotReachableException e) {
			e.printStackTrace();
		}
	}
}

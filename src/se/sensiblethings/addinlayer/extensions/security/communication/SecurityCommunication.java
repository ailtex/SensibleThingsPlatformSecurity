package se.sensiblethings.addinlayer.extensions.security.communication;

import java.nio.ByteBuffer;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Random;
import java.util.Vector;

import javax.crypto.SecretKey;

import org.apache.commons.lang.SerializationUtils;
import org.bouncycastle.jce.PKCS10CertificationRequest;

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
import se.sensiblethings.addinlayer.extensions.security.communication.message.SslConnectionMessage;
import se.sensiblethings.addinlayer.extensions.security.communication.payload.CertificateExchangePayload;
import se.sensiblethings.addinlayer.extensions.security.communication.payload.CertificatePayload;
import se.sensiblethings.addinlayer.extensions.security.communication.payload.CertificateRequestPayload;
import se.sensiblethings.addinlayer.extensions.security.communication.payload.CertificateResponsePayload;
import se.sensiblethings.addinlayer.extensions.security.communication.payload.SecretKeyPayload;
import se.sensiblethings.addinlayer.extensions.security.encryption.AsymmetricEncryption;
import se.sensiblethings.addinlayer.extensions.security.encryption.SymmetricEncryption;
import se.sensiblethings.addinlayer.extensions.security.parameters.SecurityConfiguration;
import se.sensiblethings.addinlayer.extensions.security.signature.SignatureOperations;
import se.sensiblethings.disseminationlayer.communication.Communication;
import se.sensiblethings.disseminationlayer.communication.DestinationNotReachableException;
import se.sensiblethings.disseminationlayer.communication.Message;
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
	
	/**
	 * Create a SSL connection with bootstrap node
	 * @param uci the uci who own the bootstrap node
	 * @param node the node that SSL connection is established with 
	 */
	public void createSslConnection(String uci, SensibleThingsNode node){
		//Send out the SslConnectionRequestMessage Message
		SslConnectionMessage message = new SslConnectionMessage(uci, node, communication.getLocalSensibleThingsNode());
		
		message.setSignal("Connect");
		// this message may not be secure, as if some one can hijack it
	    // if the bootstrap node can set up several different communications simultaneously
	    // the request node can just change itself communication type
		
		sendMessage(message);
		transformCommunication("SSL");
	}
	
	/**
	 *  register the self uci to bootstrap node
	 * @param toUci the boostrap's uci
	 * @param node the bootstrap node
	 * @param fromUci itself uci that will be registered
	 */
	public void register(String toUci, SensibleThingsNode node, String fromUci){
		// check local key store, whether itself has created the key pair
		
		securityManager.initializePermanentKeyStore(fromUci);
		
		RegistrationRequestMessage message = new RegistrationRequestMessage(toUci, fromUci, node, communication.getLocalSensibleThingsNode());
		
		// store the local registration Request Time
		securityManager.addToNoncePool("registrationRequestTime", message.getRegistrationRequestTime());
		
		// store the bootstrap uci
		securityManager.setBootStrapUci(toUci);
		
		sendMessage(message);
	}
	
	public void setSecuiryConfiguraton(SecurityConfiguration config){
		this.config = config;
	}
	
	public void sendSecureMassage(String message, String toUci, SensibleThingsNode toNode){
		// Get the lifeTime of keys from configuration file
		// Here for simple
		long lifeTimeInHours = 60 * 60 * 1000 * 5; 
		
		if(securityManager.isKeyValid(toUci, lifeTimeInHours)){

			sendToPostOffice(encapsulateSecueMessage(message, toUci, toNode));
			sendOutSecureMessage(toUci);
			
		}else if(securityManager.hasCertificate(toUci)){
			
			exchangeSessionKey(toUci, toNode);			
			sendToPostOffice(encapsulateSecueMessage(message, toUci, toNode));
			
		}else{
			
			exchangeCertificate(toUci, toNode);
			sendToPostOffice(encapsulateSecueMessage(message, toUci, toNode));
			
		}
	}
	
	public String handleSecureMessage(SecureMessage sm){
		return decapsulateSecureMessage(sm);
	}
	
	public void handleSslConnectionMessage(SslConnectionMessage scm) {
		if(scm.getSignal().equals("Connect")){
			// change connection type
			transformCommunication("SSL");
			
			//SslConnectionMessage requestMessage = (SslConnectionMessage)message;
			//securityListener.sslConnectionRequestEvent(requestMessage.uci, requestMessage.getFromNode());
			
		}else if(scm.getSignal().equals("Disconnect")){
			transformCommunication("RUDP");
		}
	}

	public void handleCertificateExchangeResponseMessage(
			CertificateExchangeResponseMessage cxrm) {
		//Decapsulte the Certificate
		byte[] payload = cxrm.getPayload();
		CertificateExchangePayload cxp = (CertificateExchangePayload)SerializationUtils.deserialize(payload);
		Certificate cert = cxp.getCert();
		
		// check signature
		if(!securityManager.verifySignature(cxrm.getPayload(), cxrm.getPayload(), cert, cxrm.getSignatureAlgorithm())){
			System.out.println("[Signature] Error!");
			return;
		}
		
		// check the source ID and 
		if(!cxp.getFromUci().equals(cxrm.fromUci) || !cxp.getToUci().equals(cxrm.toUci)){
			System.out.println("[ID] Error!");
			return;
		}
		
		// verify the certificate
		if (securityManager.isCertificateValid(cert, cxrm.fromUci)) {
			// store the certificate
			securityManager.storeCertificate(cxrm.fromUci, cert, "password");
			
			exchangeSessionKey(cxrm.toUci, cxrm.getToNode());
		}
	}

	public void handleCertificateExchangeMessage(CertificateExchangeMessage cxm) {
		//Decapsulte the Certificate
		byte[] payload = cxm.getPayload();
		CertificateExchangePayload cxp = (CertificateExchangePayload)SerializationUtils.deserialize(payload);
		Certificate cert = cxp.getCert();
		
		// check signature
		if(!securityManager.verifySignature(cxm.getPayload(), cxm.getPayload(), cert, cxm.getSignatureAlgorithm())){
			System.out.println("[Signature] Error!");
		}
		
		// verify the certificate
		if (securityManager.isCertificateValid(cert, cxm.fromUci)) {
			// store the certificate
			securityManager.storeCertificate(cxm.fromUci, cert, "password");
			
			// send back response message
			CertificateExchangeResponseMessage cxrm = new CertificateExchangeResponseMessage(cxm.fromUci,
					securityManager.getMyUci(), cxm.getFromNode(), communication.getLocalSensibleThingsNode());
			
			// add the uci
			cxp.setFromUci(securityManager.getMyUci());
			cxp.setToUci(cxm.fromUci);
			
			byte[] cxrmPayload = SerializationUtils.serialize(cxp);
			// set the payload
			cxrm.setPayload(cxrmPayload);
			// set the signature
			cxrm.setSignature(securityManager.signMessage(cxrmPayload, cxm.getSignatureAlgorithm()));
			// set the certificate
			cxrm.setCert(securityManager.getCertificate());
			// send
			sendMessage(cxrm);
		}
		
	}
	
	
	public void handleSessionKeyResponseMessage(SessionKeyResponseMessage skrm) {
		byte[] payload = securityManager.symmetricDecryptMessage(skrm.fromUci, skrm.getPayload(), 
				config.getSymmetricAlgorithm());
		
		// verify the signature
		if(securityManager.verifySignature(payload, skrm.getSignature(), skrm.fromUci, skrm.getSignatureAlgorithm())){
			
			ResponsePayload responsePayload = (ResponsePayload)SerializationUtils.deserialize(payload);
			if(responsePayload.getToNonce() == (Integer)securityManager.getFromNoncePool(skrm.fromUci)){
				sendOutSecureMessage(skrm.fromUci);
				securityManager.removeFromNoncePool("nonce");
			}
		}
		
	}

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
			Certificate cert = (Certificate)SerializationUtils.deserialize(skxm.getCertificatePayload());
			
			if(securityManager.isCertificateValid(cert, skxm.fromUci)){
				isValid = true;
				securityManager.storeCertificate(skxm.fromUci, cert, "password");
			}
		}
		
		if(isValid){
			// Decapsulate the key
			byte[] secretKeyPayload = skxm.getPayload();
			byte[] decryptSecretKeyPayload = 
					securityManager.asymmetricDecryptMessage(secretKeyPayload, config.getAsymmetricAlgorithm());
			
			// check the payload signature
			if(!securityManager.verifySignature(decryptSecretKeyPayload, skxm.getSignature(),
					securityManager.getPublicKey(skxm.fromUci), skxm.getSignatureAlgorithm())){
				System.out.println("[Signature] Error");
				return;
			}
			
			SecretKeyPayload payload = (SecretKeyPayload) SerializationUtils.deserialize(decryptSecretKeyPayload);
			
			// store the session key
			securityManager.storeSecretKey(skxm.fromUci, payload.getKey(),"Password");

			// send back an response message
			SessionKeyResponseMessage responseMessage = new SessionKeyResponseMessage(skxm.toUci,
					securityManager.getMyUci(), skxm.getFromNode(),
					communication.getLocalSensibleThingsNode());

			ResponsePayload responsePayload = new ResponsePayload(skxm.fromUci, securityManager.getMyUci());

			responsePayload.setFromNonce(payload.getNonce());

			// set the nonce
			int nonce = new Random().nextInt();
			responsePayload.setToNonce(nonce);
			// add it to the data pool
			securityManager.addToNoncePool(skxm.fromUci, nonce);

			byte[] responsePayloadInByte = SerializationUtils.serialize(responsePayload);
			
			responseMessage.setSignature(securityManager.signMessage(responsePayloadInByte, 
					config.getSignatureAlgorithm()));

			responseMessage.setPayload(securityManager.symmetricEncryptMessage(
							skxm.fromUci, responsePayloadInByte,
							payload.getAlgorithm()));

			sendMessage(responseMessage);
		}
	}
	

	public void handleCertificateAcceptedResponseMessage(
			CertificateAcceptedResponseMessage carm) {
		byte[] payload = securityManager.symmetricDecryptMessage(
				carm.fromUci, carm.getPayload(), config.getSymmetricAlgorithm());
		
		// convert byte array to integer
		int nonce = ByteBuffer.wrap(payload).getInt();
		
		if(nonce == (Integer)securityManager.getFromNoncePool("nonce")){
			System.out.println("[Bootstrap] Certificate has been safely accepted!");
			
			// remove the nonce from the data pool
			securityManager.removeFromNoncePool("nonce");
		}
		
	}

	public void handleCertificateResponseMessage(
			CertificateResponseMessage crm) {
		
		byte[] encryptSecretKey = crm.getEncryptSecretKey();
		// decrypt the secret key
		byte[] secretKey = securityManager.asymmetricDecryptMessage(encryptSecretKey, 
				config.getAsymmetricAlgorithm());
		
		// decrypt the certificates and nonces
		byte[] payload = securityManager.symmetricDecryptMessage(secretKey, crm.getPayload(), 
				config.getSymmetricAlgorithm());
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
					String.valueOf(nonce), config.getSymmetricAlgorithm()).getBytes());
			
			sendMessage(carm);
			
		}
	}

	public void handleCertificateRequestMessage(CertificateRequestMessage crm) {
		byte[] cipherText = crm.getPayload();
		
		// decrypt the payload
		byte[] plainText = securityManager.asymmetricDecryptMessage(cipherText, 
				config.getAsymmetricAlgorithm());
		// deserialize the payload
		CertificateRequestPayload payload = (CertificateRequestPayload)SerializationUtils.deserialize(plainText);
		// Get the certificate signing request
		PKCS10CertificationRequest certRequest = payload.getCertRequest();
		
		// check the certificate signing request
		if(securityManager.isCeritificateSigningRequestValid(certRequest, crm.fromUci)){
			Certificate[] certs = (Certificate[]) securityManager.signCertificateSigningRequest(certRequest, crm.fromUci);
			
			// generate the session key
			securityManager.generateSymmetricSecurityKey(crm.fromUci);
			
			CertificateResponseMessage certRespMesg = new CertificateResponseMessage(securityManager.getMyUci(), crm.fromUci,
															crm.getToNode(), communication.getLocalSensibleThingsNode());
			
			certRespMesg.setEncryptSecretKey(securityManager.asymmetricEncryptMessage(
								crm.fromUci, 
								securityManager.getSecretKey(crm.fromUci, "password".toCharArray()).getEncoded(),
								config.getSymmetricAlgorithm()));
			
			CertificateResponsePayload responsePayload = new CertificateResponsePayload();
			
			responsePayload.setToNonce(payload.getNonce());
			
			int toNonce = new Random().nextInt();
			responsePayload.setFromNonce(toNonce);
			// store into the data pool
			securityManager.addToNoncePool(crm.fromUci, toNonce);
			
			responsePayload.setCertChain(certs);
			
			byte[] encryptPayload = securityManager.symmetricEncryptMessage(crm.fromUci, 
					SerializationUtils.serialize(responsePayload), config.getSymmetricAlgorithm());
			
			certRespMesg.setPayload(encryptPayload);
			
			sendMessage(certRespMesg);
		}
		
	}

	public void handleRegistrationResponseMessage(
			RegistrationResponseMessage rrm) {
		
		// Construct the original request, including itself uci and request time
		String originalRequest = securityManager.getMyUci() + "," +
								securityManager.getFromNoncePool("registrationRequestTime");
		
	  	// verify the public key and the signature
		if(securityManager.verifySignature(originalRequest, 
				rrm.getSignature(), rrm.getCertificate(), rrm.getSignatureAlgorithm())){
			
			// store the bootstrap's root certificate(X509V1 version)
			securityManager.storeCertificate(rrm.uci, rrm.getCertificate(), "password");
			
			// the request is valid
			// send the ID, CSR, nonce to bootstrap node
			
			CertificateRequestMessage crm = 
					new CertificateRequestMessage(securityManager.getBootStrapUci(),
							securityManager.getMyUci(), rrm.getToNode(), communication.getLocalSensibleThingsNode());
			
			//generate an certificate signing request
			PKCS10CertificationRequest certRequest = 
					securityManager.getCertificateSigingRequest(securityManager.getMyUci());
			// set the nonce
			int nonce = new Random().nextInt();
			
			// store the nonce into the data pool
			securityManager.addToNoncePool(rrm.uci, nonce);
			
			CertificateRequestPayload payload = 
					new CertificateRequestPayload(certRequest, nonce);
			
			// use apache.commons.lang.SerializationUtils to serialize objects
			byte[] plainText = SerializationUtils.serialize(payload);
			// encrypt message
			byte[] cipherText = securityManager.asymmetricEncryptMessage(rrm.uci, plainText, 
					config.getAsymmetricAlgorithm());
			// set the encrypted payload
			crm.setPayload(cipherText);
			
			sendMessage(crm);
			
		}else{
			System.out.println("[Error] Fake signature");
		}
		
	}

	public void handleRegistrationRequestMessage(
			RegistrationRequestMessage registrationRequestMessage) {
		
		String myUci = securityManager.getMyUci();
		
		securityManager.initializePermanentKeyStore(myUci);
		
		RegistrationResponseMessage registrationResponseMessage = 
				new RegistrationResponseMessage(myUci, registrationRequestMessage.getToNode(),communication.getLocalSensibleThingsNode());
		
		// set the Root certificate from Bootstrap and send it to the applicant
		registrationResponseMessage.setCertificate(securityManager.getCertificate());
		
		// set the signature algorithm of the message
		registrationResponseMessage.setSignatureAlgorithm(config.getSignatureAlgorithm());
		
		// signed the request message
		String toBeSignedMessage =  registrationRequestMessage.fromUci + "," + 
									 registrationRequestMessage.getRegistrationRequestTime();
		
		String signature = securityManager.signMessage(toBeSignedMessage, config.getSignatureAlgorithm());
		registrationResponseMessage.setSignatue(signature);
		
		// send out the message
		sendMessage(registrationResponseMessage);
		
	}

	private void exchangeCertificate(String toUci, SensibleThingsNode toNode) {
		CertificateExchangeMessage cxm = new CertificateExchangeMessage(toUci, securityManager.getMyUci(),
				toNode, communication.getLocalSensibleThingsNode());
		
		CertificateExchangePayload cxp = new CertificateExchangePayload(securityManager.getCertificate());
		cxp.setTimeStamp(new Date());
		
		byte[] payload = SerializationUtils.serialize(cxp);
		cxm.setPayload(payload);
		cxm.setSignature(securityManager.signMessage(payload, config.getSignatureAlgorithm()));
		
		sendMessage(cxm);
	}
	
	private String decapsulateSecureMessage(SecureMessage sm){
		byte[] payload = securityManager.symmetricDecryptMessage(sm.fromUci, 
				sm.getPayload(), config.getSymmetricAlgorithm());
		
		return new String(payload);
	}
	
	private SecureMessage encapsulateSecueMessage(String message, String toUci,
			SensibleThingsNode toNode) {
		SecureMessage sm = new SecureMessage(toUci, securityManager.getMyUci(),
				toNode, communication.getLocalSensibleThingsNode());
		
		sm.setPayload(securityManager.symmetricEncryptMessage(toUci, message.getBytes(), 
				config.getSymmetricAlgorithm()));
		
		return sm;
	}

	private void exchangeSessionKey(String toUci, SensibleThingsNode toNode) {
		long lifeTimeInHours = 60 * 60 * 1000 * 5; 
		
		SessionKeyExchangeMessage skxm = new SessionKeyExchangeMessage(toUci, securityManager.getMyUci(),
				toNode, communication.getLocalSensibleThingsNode());
		
		// set the secret key payload
		securityManager.generateSymmetricSecurityKey(toUci);
		SecretKeyPayload secretKeyPayload = new SecretKeyPayload(
				(SecretKey)securityManager.getSecretKey(toUci, "password".toCharArray()),
				config.getSymmetricAlgorithm(),
				config.getSymmetricKeyLifeTime());
		
		// set nonce and add it to the data pool
		int nonce = new Random().nextInt();
		secretKeyPayload.setNonce(nonce);
		securityManager.addToNoncePool(toUci, nonce);
		
		byte[] payload = SerializationUtils.serialize(secretKeyPayload);
		byte[] encryptPayload = securityManager.asymmetricEncryptMessage(toUci, payload, 
				config.getAsymmetricAlgorithm());
		skxm.setPayload(encryptPayload);
		
		// set the secret key payload signature and the algorithm
		skxm.setSignature(securityManager.signMessage(payload, config.getSignatureAlgorithm()));
		skxm.setSignatureAlgorithm(config.getSignatureAlgorithm());
		
		// set the certificatePayload
		byte[] certificatePayload = SerializationUtils.serialize(
				new CertificatePayload(securityManager.getCertificate()));
		skxm.setCertificatePayload(certificatePayload);			
		
		sendMessage(skxm);
		
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
	
	private void sendOutSecureMessage(String toUci){
		if(postOffice.containsKey(toUci)){
			Iterator<SecureMessage> it = postOffice.get(toUci).iterator();
			while(it.hasNext()){
				sendMessage(it.next());
			}
			postOffice.get(toUci).removeAllElements();
		}
	}
	
	private void transformCommunication(String communicationType){
		if(communicationType.equals("SSL")){
			if(platform.isBehindNat()){
				platform.changeCommunicationTo(communication.PROXY_SSL);
			}else{
				SslCommunication.initCommunicationPort = 9009;
				platform.changeCommunicationTo(communication.SSL);
			}
			
			
		}else if(communicationType.equals("RUDP")){
			if(platform.isBehindNat()){
				platform.changeCommunicationTo(communication.PROXY_RUDP);
			}else{
				SslCommunication.initCommunicationPort = 9009;
				platform.changeCommunicationTo(communication.RUDP);
			}
		}
		
		this.core = platform.getDisseminationCore();
		this.communication = core.getCommunication();
		
	}
	
	
	private void sendMessage(Message message){
		try {
			communication.sendMessage(message);
		} catch (DestinationNotReachableException e) {
			e.printStackTrace();
		}
	}
}

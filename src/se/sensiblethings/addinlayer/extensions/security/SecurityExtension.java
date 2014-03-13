package se.sensiblethings.addinlayer.extensions.security;

import java.io.ObjectOutputStream;
import java.nio.ByteBuffer;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Vector;

import javax.crypto.SecretKey;

import org.apache.commons.lang.SerializationUtils;
import org.bouncycastle.jce.PKCS10CertificationRequest;

import se.sensiblethings.addinlayer.extensions.Extension;
import se.sensiblethings.addinlayer.extensions.security.communication.MessagePayload;
import se.sensiblethings.addinlayer.extensions.security.communication.ResponsePayload;
import se.sensiblethings.addinlayer.extensions.security.communication.SecureMessage;
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
import se.sensiblethings.addinlayer.extensions.security.keystore.KeyStoreTemplate;
import se.sensiblethings.addinlayer.extensions.security.keystore.SQLiteDatabase;
import se.sensiblethings.addinlayer.extensions.security.signature.SignatureOperations;
import se.sensiblethings.disseminationlayer.communication.Communication;
import se.sensiblethings.disseminationlayer.communication.DestinationNotReachableException;
import se.sensiblethings.disseminationlayer.communication.Message;
import se.sensiblethings.disseminationlayer.communication.ssl.SslCommunication;
import se.sensiblethings.disseminationlayer.disseminationcore.DisseminationCore;
import se.sensiblethings.disseminationlayer.disseminationcore.MessageListener;
import se.sensiblethings.interfacelayer.SensibleThingsNode;
import se.sensiblethings.interfacelayer.SensibleThingsPlatform;

public class SecurityExtension implements Extension, MessageListener{

	SensibleThingsPlatform platform = null;
	DisseminationCore core = null;
	Communication communication = null;
	
	SecurityListener securityListener = null;
	SecurityManager securityManager = null;
	
	Map<String, Vector<SecureMessage>> postOffice = null;
	
	public SecurityExtension(){}
	
	public SecurityExtension(SecurityListener listener){
		this.securityListener = listener;
	}
	

	@Override
	public void loadAddIn(SensibleThingsPlatform platform) {
		this.platform = platform;
		this.core = platform.getDisseminationCore();
		this.communication = core.getCommunication();
		
		//Register our own message types in the post office
		communication.registerMessageListener(SslConnectionMessage.class.getName(), this);
		communication.registerMessageListener(RegistrationRequestMessage.class.getName(), this);
		communication.registerMessageListener(RegistrationResponseMessage.class.getName(), this);
		communication.registerMessageListener(CertificateRequestMessage.class.getName(), this);
		communication.registerMessageListener(CertificateResponseMessage.class.getName(), this);
		communication.registerMessageListener(CertificateAcceptedResponseMessage.class.getName(), this);
		communication.registerMessageListener(SessionKeyExchangeMessage.class.getName(), this);
		communication.registerMessageListener(SessionKeyResponseMessage.class.getName(), this);
		communication.registerMessageListener(CertificateExchangeMessage.class.getName(), this);
		
	}

	@Override
	public void startAddIn() {
		securityManager = new SecurityManager();
		postOffice = new HashMap<String, Vector<SecureMessage>>();
	}

	@Override
	public void stopAddIn() {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void unloadAddIn() {
		// TODO Auto-generated method stub
		
	}
	
	public SecurityListener getSecurityListener() {
		return securityListener;
	}

	public void setSecurityListener(SecurityListener listener) {
		this.securityListener = listener;
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
	
	
	private void exchangeCertificate(String toUci, SensibleThingsNode toNode) {
		CertificateExchangeMessage cxm = new CertificateExchangeMessage(toUci, securityManager.getOperator(),
				toNode, communication.getLocalSensibleThingsNode());
		
		CertificateExchangePayload cxp = new CertificateExchangePayload(securityManager.getCertificate());
		cxp.setTimeStamp(new Date());
		
		byte[] payload = SerializationUtils.serialize(cxp);
		cxm.setPayload(payload);
		cxm.setSignature(securityManager.signMessage(payload, SignatureOperations.SHA256WITHRSA));
		
		sendMessage(cxm);
	}

	private SecureMessage encapsulateSecueMessage(String message, String toUci,
			SensibleThingsNode toNode) {
		SecureMessage sm = new SecureMessage(toUci, securityManager.getOperator(),
				toNode, communication.getLocalSensibleThingsNode());
		
		sm.setPayload(securityManager.symmetricEncryptMessage(toUci, message.getBytes(), 
				SymmetricEncryption.AES_CBC_PKCS5));
		
		return sm;
	}

	private void exchangeSessionKey(String toUci, SensibleThingsNode toNode) {
		long lifeTimeInHours = 60 * 60 * 1000 * 5; 
		
		SessionKeyExchangeMessage skxm = new SessionKeyExchangeMessage(toUci, securityManager.getOperator(),
				toNode, communication.getLocalSensibleThingsNode());
		
		// set the secret key payload
		securityManager.generateSymmetricSecurityKey(toUci);
		SecretKeyPayload secretKeyPayload = new SecretKeyPayload(
				(SecretKey)securityManager.getSecretKey(toUci, "password".toCharArray()),
				SymmetricEncryption.AES_CBC_PKCS5,
				lifeTimeInHours);
		
		// set nonce and add it to the data pool
		int nonce = new Random().nextInt();
		secretKeyPayload.setNonce(nonce);
		securityManager.addToNoncePool(toUci, nonce);
		
		byte[] payload = SerializationUtils.serialize(secretKeyPayload);
		byte[] encryptPayload = securityManager.asymmetricEncryptMessage(toUci, payload, "RSA");
		skxm.setPayload(encryptPayload);
		
		// set the secret key payload signature and the algorithm
		skxm.setSignature(securityManager.signMessage(payload, SignatureOperations.SHA256WITHRSA));
		skxm.setSignatureAlgorithm(SignatureOperations.SHA256WITHRSA);
		
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
	
	@Override
	public void handleMessage(Message message) {
		if(message instanceof SslConnectionMessage) {
			if(((SslConnectionMessage) message).getSignal().equals("Connect")){
				// change connection type
				transformCommunication("SSL");
				
				SslConnectionMessage requestMessage = (SslConnectionMessage)message;
				securityListener.sslConnectionRequestEvent(requestMessage.uci, requestMessage.getFromNode());
			}else if(((SslConnectionMessage) message).getSignal().equals("Disconnect")){
				transformCommunication("RUDP");
			}
			
		}else if(message instanceof RegistrationRequestMessage){
			RegistrationRequestMessage registrationRequestMessage = (RegistrationRequestMessage) message;
			handleRegistrationRequestMessage(registrationRequestMessage);
			
		}else if(message instanceof RegistrationResponseMessage){
			RegistrationResponseMessage rrm = (RegistrationResponseMessage) message;
			handleRegistrationResponseMessage(rrm);
			
		}else if(message instanceof CertificateRequestMessage){
			CertificateRequestMessage crm = (CertificateRequestMessage)message;
			handleCertificateRequestMessage(crm);

		}else if(message instanceof CertificateResponseMessage){
			CertificateResponseMessage crm = (CertificateResponseMessage)message;
			handleCertificateResponseMessage(crm);
			
		}else if(message instanceof CertificateAcceptedResponseMessage){
			CertificateAcceptedResponseMessage carm = (CertificateAcceptedResponseMessage)message;
			handleCertificateAcceptedResponseMessage(carm);
			
		}else if(message instanceof SessionKeyExchangeMessage){
			SessionKeyExchangeMessage skxm = (SessionKeyExchangeMessage)message;	
			handleSessionKeyExchangeMessage(skxm);
			
		}else if(message instanceof SessionKeyResponseMessage){
			SessionKeyResponseMessage skrm = (SessionKeyResponseMessage)message;
			handleSessionKeyResponseMessage(skrm);
			
		}else if(message instanceof CertificateExchangeMessage){
			CertificateExchangeMessage cxm = (CertificateExchangeMessage)message;
			handleCertificateExchangeMessage(cxm);
			
		}else if(message instanceof CertificateExchangeResponseMessage){
			CertificateExchangeResponseMessage cxrm = (CertificateExchangeResponseMessage)message;
			handleCertificateExchangeResponseMessage(cxrm);
		}
		
	}
	
	
	private void handleCertificateExchangeResponseMessage(
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

	private void handleCertificateExchangeMessage(CertificateExchangeMessage cxm) {
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
					securityManager.getOperator(), cxm.getFromNode(), communication.getLocalSensibleThingsNode());
			
			// add the uci
			cxp.setFromUci(securityManager.getOperator());
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
	
	
	private void handleSessionKeyResponseMessage(SessionKeyResponseMessage skrm) {
		byte[] payload = securityManager.symmetricDecryptMessage(skrm.fromUci, skrm.getPayload(), 
				SymmetricEncryption.AES_CBC_PKCS5);
		
		// verify the signature
		if(securityManager.verifySignature(payload, skrm.getSignature(), skrm.fromUci, skrm.getSignatureAlgorithm())){
			
			ResponsePayload responsePayload = (ResponsePayload)SerializationUtils.deserialize(payload);
			if(responsePayload.getToNonce() == (Integer)securityManager.getFromNoncePool(skrm.fromUci)){
				sendOutSecureMessage(skrm.fromUci);
				securityManager.removeFromNoncePool("nonce");
			}
		}
		
	}

	private void handleSessionKeyExchangeMessage(SessionKeyExchangeMessage skxm) {
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
			byte[] decryptSecretKeyPayload = securityManager.asymmetricDecryptMessage(secretKeyPayload, "RSA");
			
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
					securityManager.getOperator(), skxm.getFromNode(),
					communication.getLocalSensibleThingsNode());

			ResponsePayload responsePayload = new ResponsePayload(skxm.fromUci, securityManager.getOperator());

			responsePayload.setFromNonce(payload.getNonce());

			// set the nonce
			int nonce = new Random().nextInt();
			responsePayload.setToNonce(nonce);
			// add it to the data pool
			securityManager.addToNoncePool(skxm.fromUci, nonce);

			byte[] responsePayloadInByte = SerializationUtils.serialize(responsePayload);
			
			responseMessage.setSignature(securityManager.signMessage(responsePayloadInByte, SignatureOperations.SHA256WITHRSA));

			responseMessage.setPayload(securityManager.symmetricEncryptMessage(
							skxm.fromUci, responsePayloadInByte,
							payload.getAlgorithm()));

			sendMessage(responseMessage);
		}
	}
	

	private void handleCertificateAcceptedResponseMessage(
			CertificateAcceptedResponseMessage carm) {
		byte[] payload = securityManager.symmetricDecryptMessage(
				carm.fromUci, carm.getPayload(), SymmetricEncryption.AES_CBC_PKCS5);
		
		// convert byte array to integer
		int nonce = ByteBuffer.wrap(payload).getInt();
		
		if(nonce == (Integer)securityManager.getFromNoncePool("nonce")){
			System.out.println("[Bootstrap] Certificate has been safely accepted!");
			
			// remove the nonce from the data pool
			securityManager.removeFromNoncePool("nonce");
		}
		
	}

	private void handleCertificateResponseMessage(
			CertificateResponseMessage crm) {
		
		byte[] encryptSecretKey = crm.getEncryptSecretKey();
		// decrypt the secret key
		byte[] secretKey = securityManager.asymmetricDecryptMessage(encryptSecretKey, AsymmetricEncryption.RSA);
		
		// decrypt the certificates and nonces
		byte[] payload = securityManager.symmetricDecryptMessage(secretKey, crm.getPayload(), 
				SymmetricEncryption.AES_CBC_PKCS5);
		// deserialize
		CertificateResponsePayload responsePayload = (CertificateResponsePayload)
				SerializationUtils.deserialize(payload);
		
		// varify the nonce
		if(responsePayload.getToNonce() == (Integer)securityManager.getFromNoncePool(crm.fromUci)){
			// remove the nonce from the data pool
			securityManager.removeFromNoncePool(crm.fromUci);
			
			// store the secret key
			securityManager.storeSecretKey(crm.fromUci, secretKey, SymmetricEncryption.AES_CBC_PKCS5, "password");
			securityManager.storeCertificateChain(securityManager.getOperator(), responsePayload.getCertChain(), "password");
			
			//send back CertificateAcceptedResponseMessage
			CertificateAcceptedResponseMessage carm = 
					new CertificateAcceptedResponseMessage(crm.fromUci, securityManager.getOperator(), 
							crm.getFromNode(), communication.getLocalSensibleThingsNode());
			
			int nonce =  responsePayload.getFromNonce();
			carm.setPayload(securityManager.symmetricEncryptMessage(crm.fromUci, 
					String.valueOf(nonce), SymmetricEncryption.AES_CBC_PKCS5).getBytes());
			
			sendMessage(carm);
			
		}
	}

	private void handleCertificateRequestMessage(CertificateRequestMessage crm) {
		byte[] cipherText = crm.getPayload();
		
		// decrypt the payload
		byte[] plainText = securityManager.asymmetricDecryptMessage(cipherText, "RSA");
		// deserialize the payload
		CertificateRequestPayload payload = (CertificateRequestPayload)SerializationUtils.deserialize(plainText);
		// Get the certificate signing request
		PKCS10CertificationRequest certRequest = payload.getCertRequest();
		
		// check the certificate signing request
		if(securityManager.isCeritificateSigningRequestValid(certRequest, crm.fromUci)){
			Certificate[] certs = (Certificate[]) securityManager.signCertificateSigningRequest(certRequest, crm.fromUci);
			
			// generate the session key
			securityManager.generateSymmetricSecurityKey(crm.fromUci);
			
			CertificateResponseMessage certRespMesg = new CertificateResponseMessage(securityManager.getOperator(), crm.fromUci,
															crm.getToNode(), communication.getLocalSensibleThingsNode());
			
			certRespMesg.setEncryptSecretKey(securityManager.asymmetricEncryptMessage(
								crm.fromUci, 
								securityManager.getSecretKey(crm.fromUci, "password".toCharArray()).getEncoded(),
								SymmetricEncryption.AES_CBC_PKCS5));
			
			CertificateResponsePayload responsePayload = new CertificateResponsePayload();
			
			responsePayload.setToNonce(payload.getNonce());
			
			int toNonce = new Random().nextInt();
			responsePayload.setFromNonce(toNonce);
			// store into the data pool
			securityManager.addToNoncePool(crm.fromUci, toNonce);
			
			responsePayload.setCertChain(certs);
			
			byte[] encryptPayload = securityManager.symmetricEncryptMessage(crm.fromUci, 
					SerializationUtils.serialize(responsePayload), SymmetricEncryption.AES_CBC_PKCS5);
			
			certRespMesg.setPayload(encryptPayload);
			
			sendMessage(certRespMesg);
		}
		
	}

	private void handleRegistrationResponseMessage(
			RegistrationResponseMessage rrm) {
		
		// Construct the original request, including itself uci and request time
		String originalRequest = securityManager.getOperator() + "," +
								securityManager.getFromNoncePool("registrationRequestTime");
		
	  	// verify the public key and the signature
		if(securityManager.verifySignature(originalRequest, 
				rrm.getSignature(), rrm.getCertificate(), rrm.getSignatureAlgorithm())){
			
			// the request is valid
			// send the ID, CSR, nonce to bootstrap node
			
			CertificateRequestMessage crm = 
					new CertificateRequestMessage(securityManager.getBootStrapUci(),
							securityManager.getOperator(), rrm.getToNode(), communication.getLocalSensibleThingsNode());
			
			//generate an certificate signing request
			PKCS10CertificationRequest certRequest = 
					securityManager.getCertificateSigingRequest(securityManager.getOperator());
			// set the nonce
			int nonce = new Random().nextInt();
			
			// store the nonce into the data pool
			securityManager.addToNoncePool(rrm.uci, nonce);
			
			CertificateRequestPayload payload = 
					new CertificateRequestPayload(certRequest, nonce);
			
			// use apache.commons.lang.SerializationUtils to serialize objects
			byte[] plainText = SerializationUtils.serialize(payload);
			// encrypt message
			byte[] cipherText = securityManager.asymmetricEncryptMessage(rrm.uci, plainText, "RSA");
			// set the encrypted payload
			crm.setPayload(cipherText);
			
			sendMessage(crm);
			
		}else{
			System.out.println("[Error] Fake signature");
		}
		
	}

	private void handleRegistrationRequestMessage(
			RegistrationRequestMessage registrationRequestMessage) {
		
		String myUci = securityManager.getOperator();
		
		securityManager.initializePermanentKeyStore(myUci);
		
		RegistrationResponseMessage registrationResponseMessage = 
				new RegistrationResponseMessage(myUci, registrationRequestMessage.getToNode(),communication.getLocalSensibleThingsNode());
		
		// set the Root certificate from Bootstrap and send it to the applicant
		registrationResponseMessage.setCertificate(securityManager.getCertificate());
		
		// set the signature algorithm of the message
		registrationResponseMessage.setSignatureAlgorithm(SignatureOperations.SHA256WITHRSA);
		
		// signed the request message
		String toBeSignedMessage =  registrationRequestMessage.fromUci + "," + 
									 registrationRequestMessage.getRegistrationRequestTime();
		
		String signature = securityManager.signMessage(toBeSignedMessage, SignatureOperations.SHA256WITHRSA);
		registrationResponseMessage.setSignatue(signature);
		
		// send out the message
		sendMessage(registrationResponseMessage);
		
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

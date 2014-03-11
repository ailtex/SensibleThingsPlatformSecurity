package se.sensiblethings.addinlayer.extensions.security;

import java.io.ObjectOutputStream;
import java.nio.ByteBuffer;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Calendar;
import java.util.Date;
import java.util.Random;

import org.apache.commons.lang.SerializationUtils;
import org.bouncycastle.jce.PKCS10CertificationRequest;

import se.sensiblethings.addinlayer.extensions.Extension;
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
		communication.registerMessageListener(SslConnectionRequestMessage.class.getName(), this);
		communication.registerMessageListener(RegistrationRequestMessage.class.getName(), this);
		communication.registerMessageListener(RegistrationResponseMessage.class.getName(), this);
		communication.registerMessageListener(CertificateRequestMessage.class.getName(), this);
		communication.registerMessageListener(CertificateResponseMessage.class.getName(), this);
		communication.registerMessageListener(CertificateAcceptedResponseMessage.class.getName(), this);
		
	}

	@Override
	public void startAddIn() {
		securityManager = new SecurityManager();
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
		SslConnectionRequestMessage message = new SslConnectionRequestMessage(uci, node, communication.getLocalSensibleThingsNode());
		
		// this message may not be secure, as if some one can hijack it
	    // if the bootstrap node can set up several different communications simultaneously
	    // the request node can just change itself communication type
		
		sendMessage(message);
		transformToSslConnection();
	}
	
	public void sendSecureMassage(String message, String toUci, SensibleThingsNode toNode){
		
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
		securityManager.addToDataPool("registrationRequestTime", message.getRegistrationRequestTime());
		
		// store the bootstrap uci
		securityManager.setBootStrapUci(toUci);
		
		sendMessage(message);
	}
	
	@Override
	public void handleMessage(Message message) {
		if(message instanceof SslConnectionRequestMessage) {
			// change connection type
			transformToSslConnection();
			SslConnectionRequestMessage requestMessage = (SslConnectionRequestMessage)message;
			securityListener.sslConnectionRequestEvent(requestMessage.uci, requestMessage.getFromNode());
			
		}else if(message instanceof RegistrationRequestMessage){
			
			RegistrationRequestMessage registrationRequestMessage = (RegistrationRequestMessage) message;
			
			handleRegistrationRequestMessage(registrationRequestMessage);
			
		}else if(message instanceof RegistrationResponseMessage){
			
			RegistrationResponseMessage rrm = (RegistrationResponseMessage) message;
			
			handleRegistrationResponseMessage(rrm);
		}
		else if(message instanceof CertificateRequestMessage){
			CertificateRequestMessage crm = (CertificateRequestMessage)message;
				
			handleCertificateRequestMessage(crm);				
		}else if(message instanceof CertificateResponseMessage){
			CertificateResponseMessage crm = (CertificateResponseMessage)message;
			
			handleCertificateResponseMessage(crm);
		}else if(message instanceof CertificateAcceptedResponseMessage){
			CertificateAcceptedResponseMessage carm = (CertificateAcceptedResponseMessage)message;
			byte[] payload = securityManager.symmetricDecryptMessage(
					carm.fromUci, carm.getPayload(), SymmetricEncryption.AES_CBC_PKCS5);
			
			// convert byte array to integer
			int nonce = ByteBuffer.wrap(payload).getInt();
			
			if(nonce == (Integer)securityManager.getFromDataPool("nonce")){
				System.out.println("[Bootstrap] Certificate has been safely accepted!");
			}
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
		CertificateResponseMessagePayload responsePayload = (CertificateResponseMessagePayload)
				SerializationUtils.deserialize(payload);
		
		// varify the nonce
		if(responsePayload.getToNonce() == (Integer)securityManager.getFromDataPool("nonce")){
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
		CertificateRequestMessagePayload payload = (CertificateRequestMessagePayload)SerializationUtils.deserialize(plainText);
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
			
			CertificateResponseMessagePayload responsePayload = new CertificateResponseMessagePayload();
			
			responsePayload.setToNonce(payload.getNonce());
			
			int toNonce = new Random().nextInt();
			responsePayload.setFromNonce(toNonce);
			// store into the data pool
			securityManager.addToDataPool("nonce", toNonce);
			
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
								securityManager.getFromDataPool("registrationRequestTime");
		
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
			securityManager.addToDataPool("nonce", nonce);
			
			CertificateRequestMessagePayload payload = 
					new CertificateRequestMessagePayload(certRequest, nonce);
			
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

	
	private void transformToSslConnection(){
		if(platform.isBehindNat()){
			platform.changeCommunicationTo(communication.PROXY_SSL);
		}else{
			SslCommunication.initCommunicationPort = 9009;
			platform.changeCommunicationTo(communication.SSL);
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
	
	private String createCertificate(String info){
		// list of info :
		// uci, public key, nonce, part of certificate, hashed password
		String[] content = info.split(",");
		
		String certificate = content[0] + "," +  // uci
							 content[1] + ",";  // public key
		
		// add the validation
		Calendar calendar = Calendar.getInstance();
		calendar.setTime(new Date());
		calendar.add(Calendar.YEAR, 5);
		certificate += calendar.getTime().toString() + ",";
		
		// add part of the certificate
		certificate += content[3];
		
		return certificate;
	}
}

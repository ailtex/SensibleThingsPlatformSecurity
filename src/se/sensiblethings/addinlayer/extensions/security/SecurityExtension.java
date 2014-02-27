package se.sensiblethings.addinlayer.extensions.security;

import java.security.interfaces.RSAPrivateKey;
import java.util.Calendar;
import java.util.Date;
import java.util.Random;

import se.sensiblethings.addinlayer.extensions.Extension;
import se.sensiblethings.addinlayer.extensions.security.encryption.RSAEncryption;
import se.sensiblethings.addinlayer.extensions.security.keystore.KeyStoreTemplate;
import se.sensiblethings.addinlayer.extensions.security.keystore.SQLiteDatabase;
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
	SecurityOperations securityOperations = null;
	
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
		
		
	}

	@Override
	public void startAddIn() {
		securityOperations = new SecurityOperations();
	}

	@Override
	public void stopAddIn() {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void unloadAddIn() {
		// TODO Auto-generated method stub
		
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
			
			String myUci = securityOperations.getOperator();
			
			securityOperations.initializePermanentKeyStore(myUci);
			
			
			RegistrationResponseMessage registrationResponseMessage = 
					new RegistrationResponseMessage(myUci, registrationRequestMessage.getToNode(),communication.getLocalSensibleThingsNode());
			
			// set public key and send it to the applicant
			registrationResponseMessage.setPublicKey(securityOperations.getPublicKey());
			
			// signed the request message
			String toBeSigned_message =  registrationRequestMessage.fromUci + "," + 
										 registrationRequestMessage.registrationRequestTime;
			String signature = securityOperations.signMessage(toBeSigned_message);
			registrationResponseMessage.setSignatue(signature);
			
			sendMessage(registrationResponseMessage);
		}else if(message instanceof RegistrationResponseMessage){
			
			RegistrationResponseMessage rrm = (RegistrationResponseMessage) message;
			// verify the public key and the signature
			if(securityOperations.verifyRequest(rrm.getSignatue(), 
												rrm.getPublicKey())){
				System.out.println("[Error] Fake signature");
			}else{
				// send the ID, public key, nonce, part of certification, hashed password to bootstrap
				CertificateRequestMessage crm = 
						new CertificateRequestMessage(securityOperations.getBootStrapUci(),
													  securityOperations.getOperator(),
													  rrm.getToNode(),
												      communication.getLocalSensibleThingsNode());
				
				String part_certificate = securityOperations.signMessage(securityOperations.getOperator()+","+
																		 securityOperations.getPublicKey());
				// here set the hashed password
				String hashed_password = null;
				
				String plainText = securityOperations.getOperator() + "," + 
								   securityOperations.getPublicKey() + "," + 
						           String.valueOf(new Random().nextLong()) + "," + 
						           part_certificate + "," + 
						           hashed_password;
				
				crm.setContent(securityOperations.encryptMessage(plainText, rrm.getPublicKey()));
				sendMessage(crm);
			}
		}else if(message instanceof CertificateRequestMessage){
			CertificateRequestMessage crm = (CertificateRequestMessage)message;
			
			String plainTextMsg = securityOperations.decryptMessage(crm.getContent());
			// create the digest of the plain text message
			String certificate = createCertificate(plainTextMsg);
			
			// create the digest of the certificate
			String certificateDigest = securityOperations.digestMessage(certificate);
			// sign the certificate digest
			String certificateDigestSignature = securityOperations.signMessage(certificateDigest);
			
			
		}
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
	

	/**
	 *  register the self uci to bootstrap node
	 * @param toUci the boostrap's uci
	 * @param node the bootstrap node
	 * @param fromUci itself uci that will be registered
	 */
	public void register(String toUci, SensibleThingsNode node, String fromUci){
		// check local key store, whether itself has created the key pair
		
		securityOperations.initializePermanentKeyStore(fromUci);
		
		RegistrationRequestMessage message = new RegistrationRequestMessage(toUci, fromUci, node, communication.getLocalSensibleThingsNode());
		
		securityOperations.setRegistrationRequestTime(message.getRegistrationRequestTime());
		securityOperations.setBootStrapUci(toUci);
		sendMessage(message);
	}
	
	
	public SecurityListener getSecurityListener() {
		return securityListener;
	}

	public void setSecurityListener(SecurityListener listener) {
		this.securityListener = listener;
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
			// TODO Auto-generated catch block
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

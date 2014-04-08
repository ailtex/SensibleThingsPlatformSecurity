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
import se.sensiblethings.addinlayer.extensions.security.communication.SecurityCommunication;
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
import se.sensiblethings.addinlayer.extensions.security.communication.message.CommunicationShiftMessage;
import se.sensiblethings.addinlayer.extensions.security.communication.payload.CertificateExchangePayload;
import se.sensiblethings.addinlayer.extensions.security.communication.payload.CertificatePayload;
import se.sensiblethings.addinlayer.extensions.security.communication.payload.CertificateRequestPayload;
import se.sensiblethings.addinlayer.extensions.security.communication.payload.CertificateResponsePayload;
import se.sensiblethings.addinlayer.extensions.security.communication.payload.SecretKeyPayload;
import se.sensiblethings.addinlayer.extensions.security.configuration.SecurityConfiguration;
import se.sensiblethings.addinlayer.extensions.security.encryption.AsymmetricEncryption;
import se.sensiblethings.addinlayer.extensions.security.encryption.SymmetricEncryption;
import se.sensiblethings.addinlayer.extensions.security.keystore.IKeyStore;
import se.sensiblethings.addinlayer.extensions.security.signature.SignatureOperations;
import se.sensiblethings.disseminationlayer.communication.Communication;
import se.sensiblethings.disseminationlayer.communication.DestinationNotReachableException;
import se.sensiblethings.disseminationlayer.communication.Message;
import se.sensiblethings.disseminationlayer.communication.ssl.SslCommunication;
import se.sensiblethings.disseminationlayer.disseminationcore.DisseminationCore;
import se.sensiblethings.disseminationlayer.disseminationcore.MessageListener;
import se.sensiblethings.disseminationlayer.lookupservice.kelips.KelipsLookup;
import se.sensiblethings.interfacelayer.SensibleThingsNode;
import se.sensiblethings.interfacelayer.SensibleThingsPlatform;

public class SecurityExtension implements Extension, MessageListener{

	SensibleThingsPlatform platform = null;
	DisseminationCore core = null;
	Communication communication = null;
	
	SecurityListener securityListener = null;
	SecurityManager securityManager = null;
	SecurityCommunication securityCommunication = null;
	SecurityConfiguration config = null;
	
	String myUci = null;
	
	public SecurityExtension(SecurityListener listener, SecurityConfiguration config){
		this.securityListener = listener;
		this.config = config;
	}
	

	@Override
	public void loadAddIn(SensibleThingsPlatform platform) {
		this.platform = platform;
		this.core = platform.getDisseminationCore();
		this.communication = core.getCommunication();
		
		//Register our own message types in the post office
		communication.registerMessageListener(CommunicationShiftMessage.class.getName(), this);
		communication.registerMessageListener(RegistrationRequestMessage.class.getName(), this);
		communication.registerMessageListener(RegistrationResponseMessage.class.getName(), this);
		communication.registerMessageListener(CertificateRequestMessage.class.getName(), this);
		communication.registerMessageListener(CertificateResponseMessage.class.getName(), this);
		communication.registerMessageListener(CertificateAcceptedResponseMessage.class.getName(), this);
		communication.registerMessageListener(SessionKeyExchangeMessage.class.getName(), this);
		communication.registerMessageListener(SessionKeyResponseMessage.class.getName(), this);
		communication.registerMessageListener(CertificateExchangeMessage.class.getName(), this);
		communication.registerMessageListener(CertificateExchangeResponseMessage.class.getName(), this);
		communication.registerMessageListener(SecureMessage.class.getName(), this);

	}

	@Override
	public void startAddIn() {
		securityManager = new SecurityManager(config);
		securityCommunication = new SecurityCommunication(platform, securityManager, config);
		
	}

	@Override
	public void stopAddIn() {
		
	}

	@Override
	public void unloadAddIn() {
		
		
	}
	
	public void securityRegister(String uci){
		core.register(uci);
		
		this.myUci = uci;
		
		// Initialize the key Store, with generating its key pair and self signed certificate
		securityManager.initializeKeyStore(myUci);
		
		// Check if it's has the signed certificate
		// if it's not, it should connect to the Bootstrap and get the signed
		// certificate
		if (!securityManager.isRegisted(config.getBootstrapUci()) && !myUci.equals(config.getBootstrapUci()) ) {
			
//			SensibleThingsNode bootstrapNode = new SensibleThingsNode(
//					config.getBootstrapIP(), Integer.valueOf(config.getBootstrapPort()));
			
			SensibleThingsNode bootstrapNode = new SensibleThingsNode(KelipsLookup.bootstrapIp, 
					Integer.valueOf(config.getBootstrapPort()));
			
			securityCommunication.createSslConnection(config.getBootstrapUci(),bootstrapNode);

			securityCommunication.register(config.getBootstrapUci(), bootstrapNode);
		}

	}
	
	public void setSecurityConfiguration(SecurityConfiguration config) {
		this.config = config;
		securityManager.setSecuiryConfiguraton(config);
		securityCommunication.setSecuiryConfiguraton(config);
	}

	public SecurityListener getSecurityListener() {
		return securityListener;
	}

	public void setSecurityListener(SecurityListener listener) {
		this.securityListener = listener;
	}
	
	
	public void sendSecureMassage(String message, String toUci, SensibleThingsNode toNode){
		securityCommunication.sendSecureMassage(message, toUci, toNode);
	}
	
	
	@Override
	public void handleMessage(Message message) {
		if(message instanceof CommunicationShiftMessage) {
			CommunicationShiftMessage scm = (CommunicationShiftMessage)message;
			securityCommunication.handleCommunicationShiftMessage(scm);
			
		}else if(message instanceof RegistrationRequestMessage){
			RegistrationRequestMessage registrationRequestMessage = (RegistrationRequestMessage) message;
			securityCommunication.handleRegistrationRequestMessage(registrationRequestMessage);
			
		}else if(message instanceof RegistrationResponseMessage){
			RegistrationResponseMessage rrm = (RegistrationResponseMessage) message;
			securityCommunication.handleRegistrationResponseMessage(rrm);
			
		}else if(message instanceof CertificateRequestMessage){
			CertificateRequestMessage crm = (CertificateRequestMessage)message;
			securityCommunication.handleCertificateRequestMessage(crm);

		}else if(message instanceof CertificateResponseMessage){
			CertificateResponseMessage crm = (CertificateResponseMessage)message;
			securityCommunication.handleCertificateResponseMessage(crm);
			
		}else if(message instanceof CertificateAcceptedResponseMessage){
			CertificateAcceptedResponseMessage carm = (CertificateAcceptedResponseMessage)message;
			securityCommunication.handleCertificateAcceptedResponseMessage(carm);
			
		}else if(message instanceof SessionKeyExchangeMessage){
			SessionKeyExchangeMessage skxm = (SessionKeyExchangeMessage)message;	
			securityCommunication.handleSessionKeyExchangeMessage(skxm);
			
		}else if(message instanceof SessionKeyResponseMessage){
			SessionKeyResponseMessage skrm = (SessionKeyResponseMessage)message;
			securityCommunication.handleSessionKeyResponseMessage(skrm);
				
		}else if(message instanceof CertificateExchangeMessage){
			CertificateExchangeMessage cxm = (CertificateExchangeMessage)message;
			securityCommunication.handleCertificateExchangeMessage(cxm);
			
		}else if(message instanceof CertificateExchangeResponseMessage){
			CertificateExchangeResponseMessage cxrm = (CertificateExchangeResponseMessage)message;
			securityCommunication.handleCertificateExchangeResponseMessage(cxrm);
			
		}else if(message instanceof SecureMessage){
			SecureMessage sm = (SecureMessage)message;
			String plainText = securityCommunication.handleSecureMessage(sm);
			
			// call securityListener
			if(securityListener != null && plainText != null){
				securityListener.receivedSecureMessageEvent(plainText, sm.fromUci, sm.getFromNode());
			}
			
		}
		
	}
	
}

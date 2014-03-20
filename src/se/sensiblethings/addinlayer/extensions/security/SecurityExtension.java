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
import se.sensiblethings.addinlayer.extensions.security.communication.SecureCommunication;
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
import se.sensiblethings.addinlayer.extensions.security.parameters.SecurityLevel;
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
	SecureCommunication secureCommunication = null;
	SecurityLevel securityParameters = null;
	
	
	public SecurityExtension(SecurityListener listener, SecurityLevel level){
		this.securityListener = listener;
		this.securityParameters = level;
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
		communication.registerMessageListener(SecureMessage.class.getName(), this);
	}

	@Override
	public void startAddIn() {
		
		if(this.securityParameters == null){
			this.securityParameters = SecurityLevel.Low;
		}
		
		securityManager = new SecurityManager(securityParameters);
		secureCommunication = new SecureCommunication(this.platform, this.securityManager, this.securityParameters);
	}

	@Override
	public void stopAddIn() {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void unloadAddIn() {
		// TODO Auto-generated method stub
		
	}
	
	public SecurityLevel getSecurityParameters() {
		return securityParameters;
	}

	public void setSecurityParameters(SecurityLevel securityParameters) {
		this.securityParameters = securityParameters;
	}

	public SecurityListener getSecurityListener() {
		return securityListener;
	}

	public void setSecurityListener(SecurityListener listener) {
		this.securityListener = listener;
	}
	
	public void createSslConnection(String uci, SensibleThingsNode node){
		secureCommunication.createSslConnection(uci, node);
	}
	
	public void register(String toUci, SensibleThingsNode node, String fromUci){
		secureCommunication.register(toUci, node, fromUci);
	}
	
	
	public void sendSecureMassage(String message, String toUci, SensibleThingsNode toNode){
		secureCommunication.sendSecureMassage(message, toUci, toNode);
	}
	
	
	@Override
	public void handleMessage(Message message) {
		if(message instanceof SslConnectionMessage) {
			SslConnectionMessage scm = (SslConnectionMessage)message;
			secureCommunication.handleSslConnectionMessage(scm);
			
		}else if(message instanceof RegistrationRequestMessage){
			RegistrationRequestMessage registrationRequestMessage = (RegistrationRequestMessage) message;
			secureCommunication.handleRegistrationRequestMessage(registrationRequestMessage);
			
		}else if(message instanceof RegistrationResponseMessage){
			RegistrationResponseMessage rrm = (RegistrationResponseMessage) message;
			secureCommunication.handleRegistrationResponseMessage(rrm);
			
		}else if(message instanceof CertificateRequestMessage){
			CertificateRequestMessage crm = (CertificateRequestMessage)message;
			secureCommunication.handleCertificateRequestMessage(crm);

		}else if(message instanceof CertificateResponseMessage){
			CertificateResponseMessage crm = (CertificateResponseMessage)message;
			secureCommunication.handleCertificateResponseMessage(crm);
			
		}else if(message instanceof CertificateAcceptedResponseMessage){
			CertificateAcceptedResponseMessage carm = (CertificateAcceptedResponseMessage)message;
			secureCommunication.handleCertificateAcceptedResponseMessage(carm);
			
		}else if(message instanceof SessionKeyExchangeMessage){
			SessionKeyExchangeMessage skxm = (SessionKeyExchangeMessage)message;	
			secureCommunication.handleSessionKeyExchangeMessage(skxm);
			
		}else if(message instanceof SessionKeyResponseMessage){
			SessionKeyResponseMessage skrm = (SessionKeyResponseMessage)message;
			secureCommunication.handleSessionKeyResponseMessage(skrm);
			
		}else if(message instanceof CertificateExchangeMessage){
			CertificateExchangeMessage cxm = (CertificateExchangeMessage)message;
			secureCommunication.handleCertificateExchangeMessage(cxm);
			
		}else if(message instanceof CertificateExchangeResponseMessage){
			CertificateExchangeResponseMessage cxrm = (CertificateExchangeResponseMessage)message;
			secureCommunication.handleCertificateExchangeResponseMessage(cxrm);
			
		}else if(message instanceof SecureMessage){
			SecureMessage sm = (SecureMessage)message;
			String plainText = secureCommunication.handleSecureMessage(sm);
			
			// call securityListener
			if(securityListener != null){
				securityListener.receivedSecureMessageEvent(plainText, sm.fromUci, sm.getFromNode());
			}
			
		}
		
	}
	
}

package se.sensiblethings.addinlayer.extensions.security;

import se.sensiblethings.addinlayer.extensions.Extension;
import se.sensiblethings.addinlayer.extensions.security.keystore.DatabaseOperations;
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
	DatabaseOperations db = null;
	
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
		
	}

	@Override
	public void startAddIn() {
		
		db = new SQLiteDatabase();
		// firstly connect to permanent key store
		db.getConnection(SQLiteDatabase.PKS_DB_URL);
		//initial the database
		db.configureAndInitialize();
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
		
		try {
			// this message may not be secure, as if some one can hijack it
			// if the bootstrap node can set up several different communications simultaneously
			// the request node can just change itself communication type
			communication.sendMessage(message);
			transformToSslConnection();
		}
		catch(DestinationNotReachableException e) {
			//Do nothing
			e.printStackTrace();
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
		if(db.hasKeyPair(fromUci)){
			db.createKeyPair(fromUci);
		}
		
		RegistrationRequestMessage message = new RegistrationRequestMessage(toUci, fromUci, node, communication.getLocalSensibleThingsNode());
		
		try {
			communication.sendMessage(message);
		} catch (DestinationNotReachableException e) {
			e.printStackTrace();
		}
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
}

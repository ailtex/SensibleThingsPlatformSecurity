package se.sensiblethings.addinlayer.extensions.security;

import se.sensiblethings.addinlayer.extensions.Extension;
import se.sensiblethings.addinlayer.extensions.authentication.AuthenticationListener;
import se.sensiblethings.addinlayer.extensions.publishsubscribe.StartSubscribeMessage;
import se.sensiblethings.disseminationlayer.communication.Communication;
import se.sensiblethings.disseminationlayer.communication.DestinationNotReachableException;
import se.sensiblethings.disseminationlayer.communication.Message;
import se.sensiblethings.disseminationlayer.disseminationcore.DisseminationCore;
import se.sensiblethings.disseminationlayer.disseminationcore.MessageListener;
import se.sensiblethings.interfacelayer.SensibleThingsNode;
import se.sensiblethings.interfacelayer.SensibleThingsPlatform;

public class SecurityExtension implements Extension, MessageListener{

	SensibleThingsPlatform platform = null;
	DisseminationCore core = null;
	Communication communication = null;
	
	SecurityListener listener = null;
	
	public SecurityExtension(SecurityListener listener){
		this.listener = listener;
	}
	

	@Override
	public void loadAddIn(SensibleThingsPlatform platform) {
		this.platform = platform;
		this.core = platform.getDisseminationCore();
		this.communication = core.getCommunication();
		
		//Register our own message types in the post office
		communication.registerMessageListener(SslConnectionRequestMessage.class.getName(), this);
		//communication.registerMessageListener(SslConnectionResponseMessage.class.getName(), this);
	}

	@Override
	public void startAddIn() {
		
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
			platform.changeCommunicationTo(communication.SSL);
		}
	}

	public void createSslConnection(String uci, SensibleThingsNode node){
		//Send out the SslConnectionRequestMessage Message
		SslConnectionRequestMessage message = new SslConnectionRequestMessage(uci, node, communication.getLocalSensibleThingsNode());
		
		try {
			communication.sendMessage(message);
			
			if(platform.isBehindNat()){
				platform.changeCommunicationTo(communication.PROXY_SSL);
			}else{
				platform.changeCommunicationTo(communication.SSL);
			}
			
			this.core = platform.getDisseminationCore();
			this.communication = core.getCommunication();
		}
		catch(DestinationNotReachableException e) {
			//Do nothing
			e.printStackTrace();
		}
	}
	
	public SecurityListener getSecurityListener() {
		return listener;
	}

	public void setSecurityListener(SecurityListener listener) {
		this.listener = listener;
	}
}

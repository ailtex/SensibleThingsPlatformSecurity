package se.sensiblethings.addinlayer.extensions.security.test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Vector;

import se.sensiblethings.addinlayer.AddInManager;
import se.sensiblethings.addinlayer.extensions.security.SecurityExtension;
import se.sensiblethings.addinlayer.extensions.security.SecurityListener;
import se.sensiblethings.addinlayer.extensions.security.configuration.SecurityConfiguration;
import se.sensiblethings.disseminationlayer.communication.Communication;
import se.sensiblethings.disseminationlayer.communication.rudp.RUDPCommunication;
import se.sensiblethings.disseminationlayer.communication.ssl.SslCommunication;
import se.sensiblethings.disseminationlayer.lookupservice.LookupService;
import se.sensiblethings.disseminationlayer.lookupservice.kelips.KelipsLookup;
import se.sensiblethings.interfacelayer.SensibleThingsListener;
import se.sensiblethings.interfacelayer.SensibleThingsNode;
import se.sensiblethings.interfacelayer.SensibleThingsPlatform;




public class SecurityTestMainBootstrap implements SensibleThingsListener, SecurityListener{
	
	SensibleThingsPlatform platform = null;
	SecurityExtension secureExt = null;
	
	public static void main(String arg[]){
		SecurityTestMainBootstrap application = new SecurityTestMainBootstrap();
		application.run();
	}
	
	public SecurityTestMainBootstrap(){
		
    	//Create the platform itself with a SensibleThingsListener
		//platform = new SensibleThingsPlatform(this);
		KelipsLookup.bootstrap = true;
		KelipsLookup.bootstrapIp = getLocalHostAddress();
		
    	RUDPCommunication.initCommunicationPort = 9009;
    	platform = new SensibleThingsPlatform(LookupService.KELIPS, Communication.RUDP, this);
    	
    	AddInManager addInManager = platform.getAddInManager();
    	
    	secureExt = new SecurityExtension(this, new SecurityConfiguration("config/SecurityConfiguration.xml", 1));
    	addInManager.loadAddIn(secureExt);
    	
    	//SslCommunication.initCommunicationPort = 9009;
    	
    	//Create the platform itself with a SensibleThingsListener      
        //platform = new SensibleThingsPlatform(this);
    	//platform = new SensibleThingsPlatform(LookupService.KELIPS, Communication.RUDP, this);
    	
    	
    	//platform_ssl = new SensibleThingsPlatform(LookupService.KELIPS, Communication.SSL, this);

	}
	
	public void run(){
    	try {	    	    		
    		System.out.println("[Bootstrap Node] booted! ");

    		secureExt.securityRegister("sensiblethings@miun.se/bootstrap");
    		
    		System.out.println("[Bootstrap Node] Security Registering Successfully !");
    		
	        System.out.println("Press any key to shut down");
	        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));    	
			in.readLine();
			
			//Shutdown all background tasks
			platform.shutdown();
			
		} catch (Exception e) {
			e.printStackTrace();
		}    	
    }

	@Override
	public void getResponse(String uci, String value, SensibleThingsNode fromNode) {
		System.out.println("[Bootstrap Node : GetResponse] " + uci + ": " + fromNode + " : " + value);
		
	}

	@Override
	public void resolveResponse(String uci, SensibleThingsNode node) {
		System.out.println("[Bootstrap Node : ResolveResponse] " + uci + ": " + node);
	}

	@Override
	public void getEvent(SensibleThingsNode source, String uci) {
		System.out.println("[Bootstrap Node : GetEvent] " + uci + ": " + source);

		platform.notify(source, uci, "World!");
		
	}

	@Override
	public void setEvent(SensibleThingsNode fromNode, String uci, String value) {
		System.out.println("[Bootstrap Node : SetEvent] " + uci + ": " + value + " : " + fromNode);
		
	}
	


	@Override
	public void receivedSecureMessageEvent(String message, String uci,
			SensibleThingsNode fromNode) {
		System.out.println("[Bootstrap Node : Received SecureMessage Event] " + uci + ": " + message + " : " + fromNode);
		
	}
	
	/*
	 * find the local host IP address
	 */
    private String getLocalHostAddress() {
    	InetAddress address = null;
    	
    	try {
    		address = InetAddress.getLocalHost();
			//System.out.println(address);
		} catch (UnknownHostException e) {
			System.out.println("Could not find this computer's address.");
		}
    	
		return address.getHostAddress();
	}

}


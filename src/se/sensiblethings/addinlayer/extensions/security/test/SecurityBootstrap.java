package se.sensiblethings.addinlayer.extensions.security.test;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Random;
import java.util.Vector;

import org.bouncycastle.util.encoders.Base64;

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




public class SecurityBootstrap implements SensibleThingsListener, SecurityListener{
	
	SensibleThingsPlatform platform = null;
	SecurityExtension secureExt = null;
	
	final static String myUci = "sensiblethings@miun.se/bootstrap";
	int messageLength = 64;
	
	public static void main(String arg[]){
		SecurityBootstrap application = new SecurityBootstrap();
		application.run();
	}
	
	public SecurityBootstrap(){
		
    	//Create the platform itself with a SensibleThingsListener
		
		KelipsLookup.bootstrap = true;
		KelipsLookup.bootstrapIp = getLocalHostAddress();
		
    	RUDPCommunication.initCommunicationPort = 9009;
    	platform = new SensibleThingsPlatform(LookupService.KELIPS, Communication.RUDP, this);
    	
    	AddInManager addInManager = platform.getAddInManager();
    	
    	secureExt = new SecurityExtension(this, new SecurityConfiguration("config/SecurityConfiguration.xml", 2));
    	addInManager.loadAddIn(secureExt);
    	
	}
	
	public void run(){
    	try {	    	    		
    		System.out.println("[Bootstrap Node] booted! ");

    		// platform.register(myUci);
    		secureExt.securityRegister(myUci);
    		
    		System.out.println("[Bootstrap Node] Security Register Successfully !");
    		
    		
			// when jvm exist, delete the keyStore file
			File keystore = new File("resources/sensiblethings@miun.se_bootstrap_KeyStore.db");
			keystore.deleteOnExit();
			
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

	}

	@Override
	public void setEvent(SensibleThingsNode fromNode, String uci, String value) {
		System.out.println("[Bootstrap Node : SetEvent] " + uci + ": " + value + " : " + fromNode);
		
	}
	

	@Override
	public void receivedSecureMessageEvent(String message, String uci,
			SensibleThingsNode fromNode) {
		System.out.println("[Bootstrap Node : Received SecureMessage Event] " + uci + ": " + message + " : " + fromNode);
		
		//String value = generateMessage(messageLength);
		String value = "Welcome Back !";
		secureExt.sendSecureMassage(value, uci, fromNode);
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

    private String generateMessage(int length){
    	Random random = new Random(System.currentTimeMillis());
    	byte[] message = new byte[length];
    	random.nextBytes(message);
    	
    	return Base64.toBase64String(message);
    }
}


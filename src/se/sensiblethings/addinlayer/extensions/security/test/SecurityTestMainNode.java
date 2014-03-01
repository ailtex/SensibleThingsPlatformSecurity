package se.sensiblethings.addinlayer.extensions.security.test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.UnknownHostException;

import se.sensiblethings.addinlayer.AddInManager;
import se.sensiblethings.addinlayer.extensions.security.SecurityExtension;
import se.sensiblethings.addinlayer.extensions.security.SecurityListener;
import se.sensiblethings.disseminationlayer.communication.Communication;
import se.sensiblethings.disseminationlayer.lookupservice.LookupService;
import se.sensiblethings.disseminationlayer.lookupservice.kelips.KelipsLookup;
import se.sensiblethings.interfacelayer.SensibleThingsListener;
import se.sensiblethings.interfacelayer.SensibleThingsNode;
import se.sensiblethings.interfacelayer.SensibleThingsPlatform;


public class SecurityTestMainNode implements SensibleThingsListener, SecurityListener{
	SensibleThingsPlatform platform = null;
	SecurityExtension secureExt = null;
	
	public static void main(String[] args) {
		
		SecurityTestMainNode application = new SecurityTestMainNode();
		application.run();

	}
	
	public SecurityTestMainNode(){
		//Create the platform itself with a SensibleThingsListener
		//KelipsLookup.bootstrap = true;
		
		//KelipsLookup.bootstrapIp = "127.0.0.1";
		
		KelipsLookup.bootstrapIp = getLocalHostAddress();
		
		platform = new SensibleThingsPlatform(LookupService.KELIPS, Communication.RUDP, this);
		
		AddInManager addInManager = platform.getAddInManager();
    	
    	secureExt = new SecurityExtension(this);
    	addInManager.loadAddIn(secureExt);
		//platform = new SensibleThingsPlatform(LookupService.KELIPS, Communication.SSL, this);

	}
	
	private void run() {
		try {	    	
			System.out.println("Start to Register...!");
			
			platform.register("gausszhang@gmail.com/nodeOne");
			
			platform.resolve("gausszhang@gmail.com/server");
			
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
	public void getResponse(String uci, String value,
			SensibleThingsNode fromNode) {
		System.out.println("[GetResponse] " + uci + ": " + fromNode + " : " + value);
		
		if(value.equals("Change to SSL connetion")){
			platform.changeCommunicationTo(Communication.SSL);
			platform.set(uci, "SSL", fromNode);
		}
	}

	@Override
	public void resolveResponse(String uci, SensibleThingsNode node) {
		System.out.println("[ResolveResponse] " + uci + ": " + node);

		platform.notify(node, uci, "Secure Connection");
		
	}

	@Override
	public void getEvent(SensibleThingsNode source, String uci) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void setEvent(SensibleThingsNode fromNode, String uci, String value) {
		// TODO Auto-generated method stub
		
	}
	
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

	@Override
	public void sslConnectionRequestEvent(String uci,
			SensibleThingsNode fromNode) {
		// TODO Auto-generated method stub
		
	}
}
package se.sensiblethings.test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.UnknownHostException;

import se.sensiblethings.disseminationlayer.communication.Communication;
import se.sensiblethings.disseminationlayer.communication.rudp.RUDPCommunication;
import se.sensiblethings.disseminationlayer.communication.ssl.SslCommunication;
import se.sensiblethings.disseminationlayer.lookupservice.LookupService;
import se.sensiblethings.disseminationlayer.lookupservice.kelips.KelipsLookup;
import se.sensiblethings.interfacelayer.SensibleThingsListener;
import se.sensiblethings.interfacelayer.SensibleThingsNode;
import se.sensiblethings.interfacelayer.SensibleThingsPlatform;




public class SecurityTestMainBootstrap implements SensibleThingsListener{
	
	SensibleThingsPlatform platform;
	
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
    	//SslCommunication.initCommunicationPort = 9009;
    	
    	//Create the platform itself with a SensibleThingsListener      
        //platform = new SensibleThingsPlatform(this);
    	//platform = new SensibleThingsPlatform(LookupService.KELIPS, Communication.RUDP, this);
    	
    	platform = new SensibleThingsPlatform(LookupService.KELIPS, Communication.RUDP, this);
    	//platform_ssl = new SensibleThingsPlatform(LookupService.KELIPS, Communication.SSL, this);
    	
	}
	
	public void run(){
    	try {	    	
//    		platform.register("congcongzhang@gmail.com/superOne");
//    		System.out.println("\n superOne registered!");
    		
    		System.out.println("[Bootstrap Node] booted! ");
    		
    		//TestSuiteRangeQuery rq = new TestSuiteRangeQuery(platform);
	        //rq.performTests();
            
	        //platform.resolve("congcongzhang@gmail.com/superOne");
    		
    		platform.register("gausszhang@gmail.com/server");
    		//platform_ssl.register("gausszhang@gmail.com/server_ssl");
    		
    		
	        System.out.println("Press any key to shut down");
	        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));    	
			in.readLine();
			
			//Shutdown all background tasks
			//platform_ssl.shutdown();
			platform.shutdown();
			
		} catch (Exception e) {
			e.printStackTrace();
		}    	
    }

	@Override
	public void getResponse(String uci, String value, SensibleThingsNode fromNode) {
		System.out.println("[GetResponse] " + uci + ": " + fromNode + " : " + value);
		
		if(value.equals("Secure Connection")){
			SslCommunication.initCommunicationPort = 9009;
			platform.notify(fromNode, uci, "Change to SSL connetion");
			
			platform.changeCommunicationTo(Communication.SSL);
		}
		
	}

	@Override
	public void resolveResponse(String uci, SensibleThingsNode node) {
		System.out.println("[ResolveResponse] " + uci + ": " + node);
	}

	@Override
	public void getEvent(SensibleThingsNode source, String uci) {
		System.out.println("[GetEvent] " + uci + ": " + source);
		//platform_ssl.notify(source, uci, "Hello!");
		platform.notify(source, uci, "World!");
		
	}

	@Override
	public void setEvent(SensibleThingsNode fromNode, String uci, String value) {
		System.out.println("[SetEvent] " + uci + ": " + value + " : " + fromNode);
		
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


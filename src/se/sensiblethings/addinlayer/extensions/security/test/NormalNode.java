package se.sensiblethings.addinlayer.extensions.security.test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Random;

import org.bouncycastle.util.encoders.Base64;

import se.sensiblethings.addinlayer.extensions.security.SecurityExtension;
import se.sensiblethings.disseminationlayer.communication.Communication;
import se.sensiblethings.disseminationlayer.communication.ssl.SslCommunication;
import se.sensiblethings.disseminationlayer.lookupservice.LookupService;
import se.sensiblethings.disseminationlayer.lookupservice.kelips.KelipsLookup;
import se.sensiblethings.interfacelayer.SensibleThingsListener;
import se.sensiblethings.interfacelayer.SensibleThingsNode;
import se.sensiblethings.interfacelayer.SensibleThingsPlatform;

public class NormalNode implements SensibleThingsListener, Runnable{
	
	SensibleThingsPlatform platform = null;
	SecurityExtension secureExt = null;

	final static String myUci = "sensiblethings@miun.se/Node#1";
	
	public final static int messageLength = 10;
	public final static int messageCnt = 10;
	public final static long interval = 1000;

	long[] timestamp; 
	int count = 0;
	
	public static void main(String arg[]){
		NormalNode application = new NormalNode();
		application.run();
	}

	public NormalNode(){
		
		timestamp = new long[messageCnt+10];
		
		//Create the platform itself with a SensibleThingsListener
		//KelipsLookup.bootstrap = true;
		
		KelipsLookup.bootstrapIp = getLocalHostAddress();
		KelipsLookup.bootstrap = false;
		
		SslCommunication.initCommunicationPort = 0;
		platform = new SensibleThingsPlatform(LookupService.KELIPS, Communication.SSL, this);
		
	}
	
	@Override
	public void run(){
    	try {
    		System.out.println("[Node#1 Node] booted! ");
    		
    		platform.register(myUci);
    		
    		count = 0;
    		
    		platform.resolve("sensiblethings@miun.se/bootstrap");
    		
    		KelipsLookup.bootstrap = true;
    		
	        System.out.println("[Node#1 Node] Press any key to shut down");
	        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));    	
			in.readLine();
			
			//Shutdown all background tasks
			platform.shutdown();
			
		} catch (Exception e) {
			e.printStackTrace();
		}    	
    }

	public void shutdown(){
		platform.shutdown();
	}
	
	@Override
	public void getResponse(String uci, String value,
			SensibleThingsNode fromNode) {
		
		timestamp[count] = System.currentTimeMillis() - timestamp[count]; 
		System.out.println("[Node#1 : Get Response] "+ "#" + (count+1) + " " + uci + ": " + fromNode + " : time : " + timestamp[count]);
		
		try {
			Thread.sleep(interval);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		
		count++;
		
		if(count < messageCnt){
//			String message = String.valueOf(System.currentTimeMillis()); 
			String message = generateMessage(messageLength);
			
			timestamp[count] = System.currentTimeMillis();
			platform.notify(fromNode, uci, message);
		}else{
			
			long total = 0;
			for(int i=0;i<messageCnt;i++){
				total += timestamp[i];
			}
			
			System.out.println("[Transmission] Ended... Total time : " + total );
		}
	}

	@Override
	public void resolveResponse(String uci, SensibleThingsNode node) {
		System.out.println("[Node#1 : ResolveResponse] " + uci + ": " + node);
		
		// start testing
		String value = generateMessage(messageLength);
//		String value = String.valueOf(System.currentTimeMillis());
		
		timestamp[count] = System.currentTimeMillis();
		
		platform.notify(node, uci, value);
		
	}

	@Override
	public void getEvent(SensibleThingsNode source, String uci) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void setEvent(SensibleThingsNode fromNode, String uci, String value) {
		// TODO Auto-generated method stub
		
	}
	
	/*
	 * find the local host IP address
	 */
    private String getLocalHostAddress() {
    	InetAddress address = null;
    	
    	try {
    		address = InetAddress.getLocalHost();

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

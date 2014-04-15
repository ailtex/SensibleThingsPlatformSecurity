package se.sensiblethings.addinlayer.extensions.security.test;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.UnknownHostException;

import se.sensiblethings.addinlayer.AddInManager;
import se.sensiblethings.addinlayer.extensions.security.SecurityExtension;
import se.sensiblethings.addinlayer.extensions.security.SecurityListener;
import se.sensiblethings.addinlayer.extensions.security.configuration.SecurityConfiguration;
import se.sensiblethings.disseminationlayer.communication.Communication;
import se.sensiblethings.disseminationlayer.communication.rudp.RUDPCommunication;
import se.sensiblethings.disseminationlayer.lookupservice.LookupService;
import se.sensiblethings.disseminationlayer.lookupservice.kelips.KelipsLookup;
import se.sensiblethings.interfacelayer.SensibleThingsListener;
import se.sensiblethings.interfacelayer.SensibleThingsNode;
import se.sensiblethings.interfacelayer.SensibleThingsPlatform;

public class SecurityNode4 implements SensibleThingsListener,SecurityListener{
	SensibleThingsPlatform platform = null;
	SecurityExtension secureExt = null;

	final static String myUci = "sensiblethings@miun.se/node4";
	
	public static void main(String[] args) {

		SecurityNode4 application = new SecurityNode4();
		application.run();

	}

	public SecurityNode4() {
		
		// Create the platform itself with a SensibleThingsListener
		// KelipsLookup.bootstrap = true;
		KelipsLookup.bootstrapIp = getLocalHostAddress();

		RUDPCommunication.initCommunicationPort = 0;
		platform = new SensibleThingsPlatform(LookupService.KELIPS,
				Communication.RUDP, this);

		AddInManager addInManager = platform.getAddInManager();

		secureExt = new SecurityExtension(this, new SecurityConfiguration(
				"config/SecurityConfiguration.xml", 2));
		addInManager.loadAddIn(secureExt);

	}
	
	private void run() {
		try {
			secureExt.securityRegister(myUci);
			System.out.println("[Node#4] Registration Finished !");
			
			Thread.sleep(2000);
			platform.resolve("sensiblethings@miun.se/bootstrap");


			// when jvm exist, delete the keyStore file
			File keystore = new File("resources/sensiblethings@miun.se_node4_KeyStore.db");
			keystore.deleteOnExit();

			System.out.println("Press any key to shut down");
			BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
			in.readLine();

			// Shutdown all background tasks
			platform.shutdown();

		} catch (Exception e) {
			e.printStackTrace();
		}

	}
	
	@Override
	public void getResponse(String uci, String value,
			SensibleThingsNode fromNode) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void resolveResponse(String uci, SensibleThingsNode node) {
		System.out.println("[Node#4 : ResolveResponse] " + uci + ": " + node);
	
		secureExt.sendSecureMassage("Hello, I am " + myUci, uci, node);
	}

	@Override
	public void getEvent(SensibleThingsNode source, String uci) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void setEvent(SensibleThingsNode fromNode, String uci, String value) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void receivedSecureMessageEvent(String message, String uci,
			SensibleThingsNode fromNode) {
		System.out.println("[Node#4 : Received Secure Message] " + message );
		
	}
	
	private String getLocalHostAddress() {
		InetAddress address = null;

		try {
			address = InetAddress.getLocalHost();
			// System.out.println(address);
		} catch (UnknownHostException e) {
			System.out.println("Could not find this computer's address.");
		}

		return address.getHostAddress();
	}
	
}

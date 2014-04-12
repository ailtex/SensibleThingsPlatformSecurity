package se.sensiblethings.addinlayer.extensions.security.test;

public class NormalSSLTest {
	
	public static void main(String arg[]){
		int messageLength = 8;
		int messageCnt = 10;
		int testCnt = 10;
		
		for (int i = 0; i< testCnt; i++){
			System.out.println("[Test] Start ! : test # " + i);
			
			NormalBootstrap bootstrap = new NormalBootstrap(messageLength);
			bootstrap.run();
//			Thread bootstrapT = new Thread(bootstrap);
//			bootstrapT.start();
			
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			NormalNode node = new NormalNode(messageLength, messageCnt);
			node.run();
//			Thread nodeT = new Thread(node);
//			nodeT.start();
			
			try {
				Thread.sleep(10000);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			bootstrap.shutdown();
			node.shutdown();
		}
		
	}
	
	
}

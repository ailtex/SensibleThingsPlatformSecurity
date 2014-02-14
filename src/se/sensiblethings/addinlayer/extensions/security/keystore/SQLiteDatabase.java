package se.sensiblethings.addinlayer.extensions.security.keystore;

import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import se.sensiblethings.addinlayer.extensions.security.rsa.RSAEncryption;


public class SQLiteDatabase implements DatabaseOperations{
	
	static final String JDBC_DRIVER = "org.sqlite.JDBC";
	static final String DB_URL = "jdbc:sqlite:/Users/ailtex/Documents/workspace/SensibleThingsPlatformSecurity/tools/SensibleThingsPlatfrom.db";
	
	public static final String PKS_DB_URL = "jdbc:sqlite:/Users/ailtex/Documents/workspace/SensibleThingsPlatformSecurity/tools/PermanentKeyStore.db";
	public static final String TKS_DB_URL = "jdbc:sqlite:/Users/ailtex/Documents/workspace/SensibleThingsPlatformSecurity/tools/TemporaryKeyStore.db";
	
	Connection connection = null;
	
	@Override
	public boolean getConnection(String databaseURL) {
		//1, check if the permanent store has the public key
		//2, if not, create Public/Private key pair
		//3, use the private key sign the registration request message and send the public
		//4,
		// Permanent Key Store : PermanentKeyStore.db
		// Temporary key Store : TemporaryKeyStore.db
		// check if it already has two key store : permanent and temporary	
		
		try {
			Class.forName(JDBC_DRIVER);
			connection = DriverManager.getConnection(databaseURL);
			
		    System.out.println("[SqliteDB] Opened database successfully");
		   
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println( e.getClass().getName() + ": " + e.getMessage() );
		}
		return (connection == null) ? false : true;
		
	}

	@Override
	public boolean configureAndInitialize() {
		try {
			// set configuration
			connection.setAutoCommit(false);
			
			//check if permanentKey table already exists
			Statement statement = connection.createStatement();
			ResultSet rsExist = statement.executeQuery("select * from sqlite_master where type='table' and name ='permanentKey';");
			if(!rsExist.next()){	// if not
				String createTableSql = "create table permanentKey"+ 
										"( uci           varchar(30) primary key not null," +
										"  publicKey     blob "    +
										"  privateKey    blob"     +
										"  certification text"     +
										"  validation    timestamp)";
				
				statement.executeUpdate(createTableSql);
				statement.close();
			}
			
			
		} catch (SQLException e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}
	
	/**
	 * Check if local database stores the public key and private key 
	 * @param uci the uci who creates the public key and private key
	 * @return
	 */
	public boolean hasKeyPair(String uci){
		try {
			Statement statement = connection.createStatement();
			ResultSet rsExist = statement.executeQuery("select publicKey, privateKey from permanentKey where uci = '" + uci + "';");
			//if(rsExist.next()){
				if(rsExist.getBytes("publicKey") != null && rsExist.getBytes("privateKey")!=null ){
					return true;
				}
			//}
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return false;
	}
	
	public boolean createKeyPair(String uci){
		try {
			Statement statement = connection.createStatement();
			RSAEncryption rsa = new RSAEncryption();
			rsa.generateKey();
			
			String sql = "";
			
		} catch (SQLException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e){
			e.printStackTrace();
		}
		return true;
	}
	
	@Override
	public boolean createPermanetKeyStore() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean createTemporaryKeyStore() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public byte[] getPublicKey(String uci) {
		try {
			Statement statement = connection.createStatement();
			String sql = "select publicKey from permanentKey where uci=" + uci + ";";
			
			ResultSet result = statement.executeQuery(sql);
			return result.getBytes("publicKey");
			
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return null;
	}

	@Override
	public boolean storePublicKey(String uci, byte[] publicKey) {
		
		Map<String, String> record = new HashMap<String, String>();
		record.put("uci", uci);
		record.put("publicKey", new String(publicKey));
		return insertOperation(record);
		
		/*
		try {
			
			
			Statement statement = connection.createStatement();
			String sql = "insert into permanentKey(uci, publicKey, privateKey, certification, validation)" +
						 "values(" + uci + "," + publicKey + ","+ "'','','')";
			statement.executeUpdate(sql);
			statement.close();
			connection.commit();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return false;
		*/
	}

	@Override
	public boolean storeCertification(String uci, byte[] publicKey,
			String certification, Date validation) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean closeDatabase() {
		try {
			connection.close();
		} catch (SQLException e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

	private boolean insertOperation(Map<String, String> record){

		try {
			Statement statement = connection.createStatement();
			Iterator record
			String sql = "insert into permanentKey(uci, publicKey, privateKey, certification, validation)" + 
					     "values ('" + record.get("uci") + "'," + 
					     			   record.get("publicKey").getBytes() + "," + 
					                   record.get("privateKey").getBytes() + "," +
					     		  "'"+ record.get("certification") + "'," +
					     		       record.get("validation") + ");";
			statement.executeUpdate(sql);
			statement.close();
			connection.commit();
			return true;
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return false;
	}
	
	
}

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
import java.util.Vector;

import se.sensiblethings.addinlayer.extensions.security.encryption.RSAEncryption;


public class SQLiteDatabase implements KeyStoreTemplate{
	
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
	@Override
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
	
	// it is not the database's duty
	public boolean createKeyPair(String uci){
		// generate the RSA key pair
		RSAEncryption rsa = new RSAEncryption();
		try {
			rsa.generateKey();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		// store the key pair
		Map<String, String> record = new HashMap<String, String>();
		record.put("uci", uci);
		record.put("publicKey", new String(rsa.getPublicKey()));
		record.put("privateKey", new String(rsa.getPrivateKey()));
		return insertOperation(record);
		
	}
	

	@Override
	public byte[] getPublicKey(String uci) {
		Vector<String> property = new Vector<String>();
		property.add("publicKey");
		
		Map<String,String> result = (HashMap<String, String>)selectOperation(uci, property);
		
		return result.get("publicKey").getBytes();
	}
	
	@Override
	public byte[] getPrivateKey(String uci) {
		Vector<String> property = new Vector<String>();
		property.add("privateKey");
		
		Map<String,String> result = (HashMap<String, String>)selectOperation(uci, property);
		
		return result.get("privateKey").getBytes();
	}
	
	@Override
	public boolean storePublicKey(String uci, byte[] publicKey) {
		
		Map<String, String> record = new HashMap<String, String>();
		record.put("uci", uci);
		record.put("publicKey", new String(publicKey));
		return insertOperation(record);
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
	
	/**
	 * insert operation on permanentKey database
	 * @param record the record that will be inserted into
	 * @return
	 */
	private boolean insertOperation(Map<String, String> record){
		
		// create the sql
		String sql_partOne = "insert into permanentKey(";
		String sql_partTwo = "values (";
		
		boolean first = true;
		try {
			Statement statement = connection.createStatement();
			Iterator iterator = record.entrySet().iterator();
			while(iterator.hasNext()){
				Map.Entry entry = (Map.Entry) iterator.next(); 
				String property = (String)entry.getKey();
				String value = (String)entry.getValue();
				
				// to avoid the first ","
				if(first){
					sql_partOne += property;
					sql_partTwo += "'" + value + "'";
					first = false;
				}else{
					sql_partOne += "," + property;
					
					if(property.equals("publicKey") || property.equals("privateKey")){
						sql_partTwo += ",'" + value.getBytes() + "'";
					}else{
						sql_partTwo += ",'" + value+ "'";
					}
				}
			}
			sql_partOne += ")";
			sql_partTwo += ");";
			
			String sql = sql_partOne + sql_partTwo;
			
			statement.executeUpdate(sql);
			statement.close();
			connection.commit();
			return true;
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return false;
	}
	
	/**
	 * Update operations on permanentKey database
	 * @param uci the primary key
	 * @param record the values that would be updated
	 * @return true: run successfully
	 */
	private boolean updateOperation(String uci, Map<String, String> record){
		String sql = "update permanentKey set ";
		
		try {
			Statement statement = connection.createStatement();
			Iterator iterator = record.entrySet().iterator();
			
			boolean first = true;
			while(iterator.hasNext()){
				Map.Entry entry = (Map.Entry) iterator.next(); 
				String property = (String)entry.getKey();
				String value = (String)entry.getValue();
				
				if(first){
					if(property.equals("publicKey") || property.equals("privateKey"))
						sql += property + " = " + value.getBytes();
					else
						sql += property + " = " + value;
					
					first = false;
				}else{
					if(property.equals("publicKey") || property.equals("privateKey"))
						sql += "," + property + " = " + value.getBytes();
					else
						sql += "," + property + " = " + value;
				}
			}
			
			statement.executeUpdate(sql);
			statement.close();
			connection.commit();
		} catch (SQLException e) {
			e.printStackTrace();
		}
		
		return false;
	}
	
	/**
	 * Select operations on permanentKey databases
	 * @param uci the primary key
	 * @param property the properties that needed
	 * @return
	 */
	private Map<String,String> selectOperation(String uci, Vector<String> property){
		Map<String, String> result = new HashMap<String, String>();
		
		try {
			Statement statement = connection.createStatement();
			String sql = "select ";//publicKey from permanentKey where uci=" + uci + ";";
			
			int index = 0;
			for(; index < property.size() - 1 ; index++){
				sql += property.get(index) + ",";
			}
			sql += property.get(index) + " from permanentKey where uci=" + uci + ";";
			
			
			ResultSet resultSet = statement.executeQuery(sql);
			
			for(index = 0; index < property.size() - 1 ; index++){
				String key = property.get(index);
				String value = null;
				
				if(key.equals("privateKey") || key.equals("publicKey")){
					value = new String(resultSet.getString(key));
				}else{
					value = resultSet.getString(key);
				}
				result.put(key, value);
			}
				
		} catch (SQLException e) {
			e.printStackTrace();
		}
		
		return result;
	}
}

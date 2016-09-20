package com.bonvoyage.ogb.clientlib;


import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mongodb.BasicDBObject;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.*;

import java.io.BufferedReader;
import java.io.DataOutputStream;

import org.json.JSONException;
import org.json.JSONObject;

import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;



public class OgbClientLib {
	
	public String FrontEndServerURL;

	public OgbClientLib(String serverURL) {
		super();
		this.FrontEndServerURL = serverURL;
	}

	public String login(String userId, String tenant, String password)
	{
		String token = null;
		JSONObject loginParams = new JSONObject();
		try 
		{
			HashMap<String, String> headerParams = new HashMap<String, String>();
			headerParams.put("Content-Type", "application/json");

			loginParams.put("tenantName", tenant);
			loginParams.put("userName", userId);
			loginParams.put("password", password);

			JSONObject response = sendPost(headerParams, loginParams.toString(), FrontEndServerURL+"/OGB/user/login");
			//System.out.println("response: " + response.toString(4));

			if (response!= null)
			{
				int code = response.optInt("code", -1); 
				if (code> 199 && code < 300)
				{
					JSONObject responseObj = new JSONObject(response.optString("response"));
					token = responseObj.optString("token");
					//System.out.println("token: "+ token);
					return token;
				}
			}

		} catch (JSONException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return token;
	}



	private String insertGeoJSON(String token, String cid, String geoJSON)
	{

		try {
			String url = FrontEndServerURL+ "/OGB/content/insert/"+cid;
			HashMap<String, String> headers = new HashMap<>();
			headers.put("Authorization", token);	
			headers.put("Content-Type", "application/json");
			JSONObject result = sendPost(headers, geoJSON, url);
			if (result.optInt("code")==200) {
				//System.out.println("Insertion ok");
				JSONObject rj = new JSONObject(result.optString("response"));
				return rj.optString("oid");
				//System.out.println("SERVER REPLY, code: "+result.optInt("code")+" response: "+result.optString("response"));
			} else {
				System.out.println("Insertion failed");
				System.out.println("SERVER REPLY, code: "+result.optInt("code")+" response: "+result.optString("response"));
				return null;
			}

		} catch (Exception  ex) {
			System.err.println(ex);
		} 
		return null;
	}

	public boolean deleteObject(String token, String cid, String oid) {
		String url = FrontEndServerURL+ "/OGB/content/delete/"+cid;
		HashMap<String, String> headers = new HashMap<>();
		headers.put("Authorization", token);	
		headers.put("Content-Type", "application/json");
		String json = "{\"oid\": \""+oid+"\"}";
		JSONObject result = sendPost(headers, json, url);
		if (result.optInt("code")==200) {
			//System.out.println("Insertion ok");
			//JSONObject rj = new JSONObject(result.optString("response"));

			//System.out.println("SERVER REPLY, code: "+result.optInt("code")+" response: "+result.optString("response"));
			return true;
		} else {
			System.out.println("Delete failed");
			System.out.println("SERVER REPLY, code: "+result.optInt("code")+" response: "+result.optString("response"));    		
		}   
		return false;
	}

	@SuppressWarnings("unused")
	private JSONObject sendPostU(Map<String, String> headerParams, String postParams, String url) {

		try {
			
			HttpURLConnection urlConnection = (HttpURLConnection)new URL(url).openConnection();
			urlConnection.setRequestMethod("POST");
			urlConnection.setDoOutput(true);

			for (String key : headerParams.keySet())
				urlConnection.setRequestProperty(key, headerParams.get(key));

			//long start = System.currentTimeMillis();
			DataOutputStream streamWriter = new DataOutputStream(urlConnection.getOutputStream());
			streamWriter.writeBytes(postParams.toString());
			streamWriter.flush();
			streamWriter.close();

			int responseCode = urlConnection.getResponseCode();
			//System.out.println("Real post time: "+(System.currentTimeMillis()-start));

			InputStream inputStream;
			if (responseCode >= 200 && responseCode < 300)
				inputStream = urlConnection.getInputStream();
			else
				inputStream = urlConnection.getErrorStream();

			StringBuffer   response     = new StringBuffer();
			BufferedReader streamReader = new BufferedReader(new InputStreamReader(inputStream));

			String inputLine;
			while ( (inputLine = streamReader.readLine()) != null)
				response.append(inputLine);
			streamReader.close();


			JSONObject result = new JSONObject();
			result.put("code",responseCode);
			result.put("response",response.toString());

			return result;
		} 
		catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	private JSONObject sendPost(Map<String, String> headerParams, String postParams, String url) {

		try {
			// Create a trust manager that does not validate certificate chains
	        TrustManager[] trustAllCerts = new TrustManager[] {
	        	new X509TrustManager() {
	                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
	                    return null;
	                }
	               
					@Override
					public void checkClientTrusted(X509Certificate[] chain, String authType)
							throws CertificateException {
					}
					@Override
					public void checkServerTrusted(X509Certificate[] chain, String authType)
							throws CertificateException {
					}
	            }
	        };
	 
	        // Install the all-trusting trust manager
	        SSLContext sc = SSLContext.getInstance("SSL");
	        sc.init(null, trustAllCerts, new java.security.SecureRandom());
	        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
	 
	        // Create all-trusting host name verifier
	        HostnameVerifier allHostsValid = new HostnameVerifier() {
	            public boolean verify(String hostname, SSLSession session) {
	                return true;
	            }
	        };
	 
	        // Install the all-trusting host verifier
	        HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
			HttpsURLConnection urlConnection = (HttpsURLConnection)new URL(url).openConnection();
			urlConnection.setRequestMethod("POST");
			urlConnection.setDoOutput(true);

			for (String key : headerParams.keySet())
				urlConnection.setRequestProperty(key, headerParams.get(key));

			//long start = System.currentTimeMillis();
			DataOutputStream streamWriter = new DataOutputStream(urlConnection.getOutputStream());
			streamWriter.writeBytes(postParams.toString());
			streamWriter.flush();
			streamWriter.close();

			int responseCode = urlConnection.getResponseCode();
			//System.out.println("Real post time: "+(System.currentTimeMillis()-start));

			InputStream inputStream;
			if (responseCode >= 200 && responseCode < 300)
				inputStream = urlConnection.getInputStream();
			else
				inputStream = urlConnection.getErrorStream();

			StringBuffer   response     = new StringBuffer();
			BufferedReader streamReader = new BufferedReader(new InputStreamReader(inputStream));

			String inputLine;
			while ( (inputLine = streamReader.readLine()) != null)
				response.append(inputLine);
			streamReader.close();


			JSONObject result = new JSONObject();
			result.put("code",responseCode);
			result.put("response",response.toString());

			return result;
		} 
		catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}



	public String addPoint(String token, String cid, HashMap<String, String> propertiesMap, final double[] location)
	{
		double x = location[0];
		double y = location[1];
		boolean first=true;
		String oid = null;
		String json = "{\"geometry\" : {\"type\" : \"Point\", \"coordinates\" : ["+ x + ", " + y +"]},\"type\":\"Feature\", \"properties\" : {";
		
		for (String key : propertiesMap.keySet()) {
			if (!first)
				json = json+",";
			else
				first=false;
			
			json = json +"\""+key+"\" : \""+propertiesMap.get(key)+"\"";
		}
		
		json = json+"}}";
		System.out.println("geoJSON to be inserted: "+json);
		if (!isJSONValid(json))
			System.out.println("Not valid GeoJSON");
		else
			oid=insertGeoJSON(token, cid, json);

		return oid;
	}

	public String addMultiPoint(String token, String cid, HashMap<String, String> propertiesMap, ArrayList<double[]> coordinates )
	{
		boolean first=true;
		String oid = null;
		String json = "{\"geometry\" : {\"type\" : \"MultiPoint\", \"coordinates\" : [";
		
		for (int i = 0; i < coordinates.size(); i++) {
			double x=coordinates.get(i)[0];
			double y=coordinates.get(i)[1];
			if (i>0) json += ",";
			json = json + "["+ x + ", " + y +"]";
		}
		json = json + "]},\"type\":\"Feature\", \"properties\" : {";

		for (String key : propertiesMap.keySet()) {
			if (!first)
				json = json+",";
			else
				first=false;

			json = json +"\""+key+"\" : \""+propertiesMap.get(key)+"\"";
		}
		json = json+"}}";
		
		System.out.println("geoJSON to be inserted: "+json);
		if (!isJSONValid(json))
			System.out.println("Not valid GeoJSON");
		else
			oid=insertGeoJSON(token, cid, json);

		return oid;
	}

	public String rangeQuery(String token, String cid, double sw_lat, double sw_lon, double boxSize) 
	{
		try {
			List<double[]> box = new ArrayList<double[]>();
			box.add(new double[] { sw_lat, sw_lon }); //Starting coordinate
			box.add(new double[] {sw_lat+boxSize, sw_lon+boxSize }); // Ending coordinate

			BasicDBObject geometryValue = new BasicDBObject("type","Box");
			geometryValue.append("coordinates", box);
			BasicDBObject geometry = new BasicDBObject("$geometry",geometryValue);
			BasicDBObject queryType = new BasicDBObject("$geoIntersects",geometry);
			BasicDBObject query = new BasicDBObject("geometry",queryType);
			//System.out.println(query);

			String url = FrontEndServerURL+ "/OGB/query-service/"+cid;
			HashMap<String, String> headers = new HashMap<>();
			headers.put("Authorization", token);	
			headers.put("Content-Type", "application/json");
			JSONObject result = sendPost(headers, query.toString(), url);

			//System.out.println("SERVER REPLY, code: "+result.optInt("code")+" response length (bytes): "+result.optString("response").length());
			//System.out.println("SERVER REPLY, code: "+result.optInt("code")+" response: "+result.optString("response"));
			return result.optString("response");
		}
		catch(Exception e) {
			System.err.println( e.getClass().getName() + ": " + e.getMessage() );
		}
		
		return null;
	}
	
	/***
	 * 
	 * @param json represnet the json string that you want to check
	 * @return true if the json passed as argument is parsable by JsonParser. Return false otherwise.
	 */
	private boolean isJSONValid(final String json) 
	{
		boolean valid = false;
		
		try {
			final JsonParser parser = new ObjectMapper().getFactory().createParser(json);
			while (parser.nextToken() != null) {
			}
			valid = true;
		}
		catch (JsonParseException jpe) {
			jpe.printStackTrace();
		}
		catch (IOException ioe) {
			ioe.printStackTrace();
		}
		
		return valid;

	}
	
	/***
	 * 
	 * @param args
	 * 
	 */
	public static void main( String args[] ) {
		
		String serverURL = "https://192.168.0.1:443";
		String token;
		
		String uid = "admin";	// user id
		String tid = "mytid";	// tenant id
		String pwd = "myogb";	// password
		String cid = "mycid";	// collection id

		OgbClientLib ogbTestClient = new OgbClientLib(serverURL);

		// LOGIN
		token=ogbTestClient.login(uid, tid, pwd);	// get token for HTTP next interactions
		if (token!= null) {
			System.out.println("Authentication ok, token: "+token);
		} 
		else {
			System.out.println("Authentication failure");
			System.exit(-1);
			return;
		}

		// INSERTION OF POINT OBJECT 
		System.out.println("\n**** Point geoJSON Insert ****\n\n");
		// point coordinates, where latitude is the first and latitude the second
		double [] coordinates = {0.1, 0.1};
		// point properties
		HashMap<String,String> prop = new HashMap<String,String>();
		prop.put("prop100", "value100");	
		prop.put("prop200", "value200");
		// db insertion, response is the object identifier (oid)
		String oid = ogbTestClient.addPoint(token,cid, prop, coordinates);
		if (oid != null) {
			System.out.println("Insertion ok, oid : "+oid);
		}
		else {
			System.exit(-1);
			return;
		}

		// Sleep necessary to allow backend to finish insert procedure, otherwise range query could not return the inserted item
		try {
			Thread.sleep(200);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}

		// RANGE QUERY, response is a JSON Array
		System.out.println("\n**** Range Query ****\n\n");
		String response = ogbTestClient.rangeQuery(token, cid, 0.0, 0.0, 0.5);
		System.out.println("query response: " + response);

		// DELETE OBJECT
		System.out.println("**** Delete object ****\n\n");
		if (ogbTestClient.deleteObject(token, cid, oid)) {
			System.out.println("Delete of " + oid+" OK");
		};

		try {
			Thread.sleep(200);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// RANGE QUERY, response is a JSON Array
		System.out.println("\n**** Range Query ****\n");
		response = ogbTestClient.rangeQuery(token, cid, 0.0, 0.0, 0.5);
		System.out.println("query response: " + response);


		// INSERTION OF MULTI-POINT OBJECT 
		System.out.println("\n**** MultiPoint geoJSON Insert ****\n\n");
		// multipoint coordinate

		ArrayList<double[]> mcoordinates = new ArrayList<double[]>();
		mcoordinates.add(new double[] { 0.1, 0.1 }); //point 1
		mcoordinates.add(new double[]{0.11, 0.11 }); // point 2
		// point properties
		HashMap<String,String> mprop = new HashMap<String,String>();
		mprop.put("prop100", "value100");	
		mprop.put("prop200", "value200");

		// db insertion, response is the object identifier (oid)
		String moid = ogbTestClient.addMultiPoint(token,cid, mprop, mcoordinates);
		if (moid!=null) {
			System.out.println("Insertion ok, oid : "+moid);
		} else {
			return;
		}
		try {
			Thread.sleep(200);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}


		// RANGE QUERY, response is a JSON Array
		System.out.println("\n**** Range Query ****\n");
		response = ogbTestClient.rangeQuery(token, cid, 0.0, 0.0, 0.5);
		System.out.println("query response: " + response);

		// DELETE OBJECT
		System.out.println("**** Delete object ****\n\n");
		if (ogbTestClient.deleteObject(token, cid, moid)) {
			System.out.println("Delete of " + moid+" OK");
		};

		try {
			Thread.sleep(200);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		

		// RANGE QUERY, response is a JSON Array
		System.out.println("\n**** Range Query ****\n");
		response = ogbTestClient.rangeQuery(token, cid, 0.0, 0.0, 0.5);
		System.out.println("query response: " + response);

		
	}
}
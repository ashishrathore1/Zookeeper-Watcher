package com.snapdeal.vault;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Properties;


import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class CreateUser {
	
	private HttpClient httpClient;
	private HttpPost postRequest;
	private HttpPut putRequest;
	private String vaultTokenHeader="X-Vault-Token";
	private String apiUrl;
	private HttpResponse responseStmt;
	private StatusLine responseString;
	private HashString hashUserId;
	private String userid;
	private PropertyValues propertyValues;
	private String jssecacertPath;
	private String baseURL="https://";
	private String version="/v1/";
	private String vaultIP;
	private String port;
	private String pathurl;

	
	private final Logger logger = LoggerFactory.getLogger(CreateUser.class);
	
	public CreateUser() throws KeyManagerConnectionException {
		propertyValues=new PropertyValues();
		this.jssecacertPath=propertyValues.getJssecacerPath();
		this.vaultIP=propertyValues.getVaultIP();
		this.port=propertyValues.getPort();
		this.jssecacertPath=propertyValues.getJssecacerPath();
		Properties systemProperties = System.getProperties();
		systemProperties.put( "javax.net.ssl.trustStore", jssecacertPath);
		System.setProperties(systemProperties);
		hashUserId = new HashString();
		httpClient = HttpClientBuilder.create().build();
	}
	
	
	public int createAppId(String path,String clienttoken) throws ClientProtocolException, IOException {
		int status=400;
		String hashServiceName;	
			if(path.startsWith("/smartstack/services/")){
				path=path.replaceFirst("/smartstack/services/", "");
				StringBuilder servicename = new StringBuilder();
				StringBuilder policyname = new StringBuilder();
				StringBuilder policypath = new StringBuilder();
				policypath.append("secret/");
				int index=0,countslash=0;
				while(countslash!=3){
					if(path.charAt(index)=='/'){
						countslash++;
						if(countslash!=3){
							policyname.append("_");
							policypath.append("/");
						}
					}else{
						servicename.append(path.charAt(index));
						policyname.append(path.charAt(index));
						policypath.append(path.charAt(index));
					}
					index++;
				}
				
				String policyjson = "{ \"name\":\""+policyname.toString()+"\",\"rules\":\""+
						"{\\\"path\\\": {\\\"sys/*\\\": {\\\"policy\\\": \\\"deny\\\"},"+
						"\\\""+policypath.toString()+"\\\": {\\\"policy\\\": \\\"read\\\"}, \\\"auth/token/lookup-self\\\": {\\\"policy\\\": \\\"read\\\"}}}\" }";
				
				if(createPolicy(policyjson, policyname.toString(),clienttoken)!=204){
					logger.error("Error: In policy creation");
					return status;
				}else{
					logger.info("policy created"+policyname.toString());
				}
				
				try {
					hashServiceName=hashUserId.makeSHA1Hash(servicename.toString());
					pathurl = "auth/app-id/map/app-id/"+hashServiceName;
					apiUrl =  baseURL  + vaultIP + ":" + port + version +  pathurl ;
					postRequest = new HttpPost(apiUrl);
					postRequest.addHeader(vaultTokenHeader, clienttoken);
					StringEntity policy = new StringEntity("{\"value\":\""+policyname.toString()+"\",\"display_name\":\""+policyname.toString()+"\"}","UTF-8");
					policy.setContentType("application/json");
					postRequest.setEntity(policy);
					responseStmt = httpClient.execute(postRequest);
					StatusLine statusLine = responseStmt.getStatusLine();
					int statusCode = statusLine.getStatusCode();
					logger.info("policy creation status code"+statusCode);
					
					if(statusCode/100==3){
						apiUrl= responseStmt.getFirstHeader("Location").getValue();
						postRequest = new HttpPost(apiUrl);
						postRequest.addHeader(vaultTokenHeader, clienttoken);
						postRequest.setEntity(policy);
						responseStmt = httpClient.execute(postRequest);
						statusLine = responseStmt.getStatusLine();
						statusCode = statusLine.getStatusCode();
						
					}
					
					if(statusCode==204)
					{
						status=200;
						System.out.println("appid:"+hashServiceName);
						logger.info("App-id created in vault"); 
					}
					else
					{
						logger.error("Error in creating Appid status:"+statusCode);
					}
						
				} catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
					logger.error("ERROR CREATING APPID", e);
				}
				
			}
				

		return status;
	}

	
	
	public int createUserId(String name,String path,String clienttoken){
		
		int status=400;
		String appidvalue;
		if(path.startsWith("/smartstack/services/")){
			path=path.replaceFirst("/smartstack/services/", "");
			StringBuilder servicename = new StringBuilder();
			int index=0,countslash=0;
			while(countslash!=3){
				if(path.charAt(index)=='/'){
					countslash++;
				}else{
					servicename.append(path.charAt(index));
				}
				index++;
			}	

			try
			{	
				appidvalue=hashUserId.makeSHA1Hash(servicename.toString());
				JSONObject dataHost = new JSONObject(name);
				userid = hashUserId.makeSHA1Hash(dataHost.getString("host")+dataHost.getString("name")+String.valueOf(dataHost.getInt("port")));
				pathurl = "auth/app-id/map/user-id/"+userid;
				apiUrl =  baseURL  + vaultIP + ":" + port + version +  pathurl ;
				postRequest = new HttpPost(apiUrl);
				postRequest.addHeader(vaultTokenHeader, clienttoken);
				StringEntity appid = new StringEntity("{\"value\":\""+appidvalue+"\"}","UTF-8");
				appid.setContentType("application/json");
				postRequest.setEntity(appid);
				responseStmt = httpClient.execute(postRequest);
				StatusLine statusLine = responseStmt.getStatusLine();
				int statusCode = statusLine.getStatusCode();
				
				if(statusCode/100==3){
					apiUrl= responseStmt.getFirstHeader("Location").getValue();
					postRequest = new HttpPost(apiUrl);
					postRequest.addHeader(vaultTokenHeader, clienttoken);
					postRequest.setEntity(appid);
					responseStmt = httpClient.execute(postRequest);
					statusLine = responseStmt.getStatusLine();
					statusCode = statusLine.getStatusCode();
				}
				
				if(statusCode==204)
				{
					status=200;
					System.out.println("userid:"+userid);
					logger.info("User created in vault"); 
				}
				else
				{
					logger.error("Error in creating userid status:"+statusCode);
				}
			}
			catch(Exception e)
			{
				logger.error("ERROR CREATING USERID", e);
			}
			
		}
		
		return status;
		
	}
	
	
	public int createPolicy(String policyjson, String policyname,String clienttoken) {
		// TODO Auto-generated method stub
		int statusCode;
		pathurl = "sys/policy/";
		apiUrl = baseURL + vaultIP + ":" + port + version +  pathurl + policyname;
		httpClient = HttpClientBuilder.create().build();
		putRequest = new HttpPut(apiUrl);
		putRequest.addHeader(vaultTokenHeader, clienttoken);
		StringEntity entity = new StringEntity(policyjson, StandardCharsets.UTF_8);
		entity.setContentType("application/json");
		putRequest.setEntity(entity);
		try {
			
			
			responseStmt = httpClient.execute(putRequest);
			responseString=responseStmt.getStatusLine();
			statusCode=responseString.getStatusCode();
			if(statusCode/100 ==3){
				apiUrl= responseStmt.getFirstHeader("Location").getValue();
				httpClient = HttpClientBuilder.create().build();
				putRequest = new HttpPut(apiUrl);
				putRequest.addHeader(vaultTokenHeader, clienttoken);
				putRequest.setEntity(entity);
				responseStmt = httpClient.execute(putRequest);
				responseString=responseStmt.getStatusLine();
				statusCode=responseString.getStatusCode();				
			}
			
		} catch (ClientProtocolException e) {
			logger.error("ClientProtocolException", e);
			return 0;
		} catch (IOException e) {
			logger.error("IOException", e);
			return 0;
		}
		return statusCode;
	}



}

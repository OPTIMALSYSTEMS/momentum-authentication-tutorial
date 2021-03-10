package com.os.enaio.cloud.tutorial;

import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import okhttp3.CookieJar;
import okhttp3.Headers;
import okhttp3.JavaNetCookieJar;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.apache.commons.io.FileUtils;
import org.junit.Before;
import org.junit.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.awt.Desktop;
import java.io.File;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class AuthenticationTests
{
	private String userName = "root";
	private String userPwd = "optimal";
	private String userTenant = "default";
	private String clientId = "enaio";
	private String clientSecret = "6926e96c-781b-40db-af5f-e410cd7e6ce4";
	private String enaioBaseUrl = "http://localhost";
	private String keycloakBaseUrl = "https://localhost:8443";

	private OkHttpClient client = null;

	// necessary to obtain access tokens via SSL
	X509TrustManager trustManager = new X509TrustManager()
	{
		public void checkClientTrusted(X509Certificate[] x509Certificates, String s) {}
		public void checkServerTrusted(X509Certificate[] x509Certificates, String s) {}
		public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
	};

	@Before
	public void init() throws Exception
	{
		// delete cookies from preceding test run
		CookieJar cookieJar = new JavaNetCookieJar(new CookieManager(null, CookiePolicy.ACCEPT_ALL));

		SSLContext sslContext = SSLContext.getInstance("SSL");
		sslContext.init(null, new TrustManager[]{this.trustManager}, new SecureRandom());

		// create HTTP Client
		this.client = new OkHttpClient.Builder()
						.cookieJar(cookieJar)
						.hostnameVerifier((s, sslSession) -> true)
						.sslSocketFactory(sslContext.getSocketFactory(), this.trustManager)
						.build();
	}

	@Test
	public void authenticateWithUsernameAndPassword() throws Exception
	{
		// decode credentials with Base64 for Basic Authentication
		Headers.Builder headers = new Headers.Builder()
						.add("Authorization", "Basic " + Base64.getEncoder().encodeToString((this.userName + ":" + this.userPwd).getBytes(StandardCharsets.UTF_8)))
						.add("X-ID-TENANT-NAME", this.userTenant);

		this.sendSearchRequest(headers.build());
	}

	@Test
	public void authenticateWithAccessToken() throws Exception
	{
		// obtain an access token from Keycloak

		String payload = "client_id="     + this.clientId     + "&" +
		                 "client_secret=" + this.clientSecret + "&" +
		                 "username="      + this.userName     + "&" +
		                 "password="      + this.userPwd      + "&" +
		                 "grant_type=password";

		Request.Builder request = new Request.Builder()
						.url(this.keycloakBaseUrl + "/auth/realms/" + this.userTenant + "/protocol/openid-connect/token")
						.post(RequestBody.create(MediaType.parse("application/x-www-form-urlencoded"), payload));

		String responseJson = this.client.newCall(request.build()).execute().body().string();
		DocumentContext context = JsonPath.parse(responseJson);
		String tokenType = context.read("token_type");
		String accessToken = context.read("access_token");

		// authenticate with access token

		Headers.Builder headers = new Headers.Builder()
						.add("Authorization", tokenType + " " + accessToken)
						.add("X-ID-TENANT-NAME", this.userTenant);

		this.sendSearchRequest(headers.build());
	}

	@Test
	public void authenticateWithDeviceFlow() throws Exception
	{
		// start device flow authentication

		Request.Builder startRequest = new Request.Builder().url(this.enaioBaseUrl + "/tenant/" + this.userTenant + "/loginDevice");

		String responseJson = this.client.newCall(startRequest.build()).execute().body().string();
		DocumentContext context = JsonPath.parse(responseJson);

		String deviceCode = context.read("device_code");
		String userCode = context.read("user_code");
		String verificationUri = context.read("verification_uri");

		// open verification URI in browser

		Desktop.getDesktop().browse(new URI(this.enaioBaseUrl + verificationUri + "?user_code=" + userCode));

		// start polling for access token (with a two-second interval)

		String tokenType = null;
		String accessToken = null;

		for (int i = 1 ; i != 30 ; i++, Thread.sleep(2000))
		{
			Request.Builder pollingRequest = new Request.Builder().url(this.enaioBaseUrl + "/auth/info/state?device_code=" + deviceCode);
			Response pollingResponse = this.client.newCall(pollingRequest.build()).execute();

			if (pollingResponse.code() != 200) continue;

			context = JsonPath.parse(pollingResponse.body().string());
			tokenType = context.read("token_type");
			accessToken = context.read("access_token");

			break;
		}

		// authenticate with access token

		Headers.Builder headers = new Headers.Builder()
						.add("Authorization", tokenType + " " + accessToken)
						.add("X-ID-TENANT-NAME", this.userTenant);

		this.sendSearchRequest(headers.build());
	}

	private void sendSearchRequest(Headers headers) throws Exception
	{
		// send request with authorization header
		String searchQuery = FileUtils.readFileToString(new File("src/test/resources/search_query.json"), StandardCharsets.UTF_8);

		Request.Builder request = new Request.Builder()
						.url(this.enaioBaseUrl + "/api/dms/objects/search")
						.headers(headers)
						.post(RequestBody.create(MediaType.parse("application/json"), searchQuery));

		Response response = this.client.newCall(request.build()).execute();
		System.out.println("hit list: " + response.body().string());
	}
}
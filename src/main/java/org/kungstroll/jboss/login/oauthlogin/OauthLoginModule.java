package org.kungstroll.jboss.login.oauthlogin;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.Principal;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import org.slf4j.Logger;
import org.apache.activemq.jaas.GroupPrincipal;
import org.apache.activemq.jaas.UserPrincipal;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;

import org.slf4j.LoggerFactory;

/**
 *
 *
 * ${provider_id} ${provider_user_id}
 *
 * @author <a href="jens.brimberg@gmail.com">jens brimberg</a>
 */
public class OauthLoginModule implements LoginModule {

	private final Logger logger = LoggerFactory.getLogger(OauthLoginModule.class.getName());
	private Subject subject;
	private CallbackHandler callbackHandler;
	private final Set<Principal> principals = new HashSet<>();

	private Connection conn;
	private String db_url,
			db_user,
			db_pass,
			db_driver,
			query_get_user,
			query_add_user,
			query_get_groups;
	private final HashMap<String, String> tokenUrlMap = new HashMap<>(),
			userUrlMap = new HashMap<>(),
			logoutUrlMap = new HashMap<>(),
			providerMap = new HashMap<>(),
			clientIdMap = new HashMap<>(),
			secretMap = new HashMap<>();

	@Override
	public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
		this.subject = subject;
		this.callbackHandler = callbackHandler;

		for (String option : options.keySet()) {
			if (option.toLowerCase().endsWith("_provider")) {
				Object tokenUrl = options.get(option.toLowerCase() + "_token");
				Object userUrl = options.get(option.toLowerCase() + "_user");
				Object logoutUrl = options.get(option.toLowerCase() + "_logout");

				Object client_id = options.get(option.toLowerCase() + "_client_id");
				Object secret = options.get(option.toLowerCase() + "_secret");

				if (tokenUrl == null) {
					logger.warn("No 'token url' option set for provider '" + option + "'.");
				} else if (userUrl == null) {
					logger.warn("No 'user url' option set for provider '" + option + "'.");
				} else if (client_id == null) {
					logger.warn("No 'client_id' option set for provider '" + option + "'.");
				} else if (secret == null) {
					logger.warn("No 'secret' option set for provider '" + option + "'.");
				} else {
					providerMap.put(options.get(option).toString(), option);
					tokenUrlMap.put(option, tokenUrl.toString());
					userUrlMap.put(option, userUrl.toString());
					if (logoutUrl != null) {
						logoutUrlMap.put(option, logoutUrl.toString());
					}
					clientIdMap.put(option, client_id.toString());
					secretMap.put(option, secret.toString());
				}
			}
		}

		this.db_url = options.get("db_url").toString();
		this.db_user = options.get("db_user").toString();
		this.db_pass = options.get("db_pass").toString();
		this.db_driver = options.get("db_driver").toString();

		this.query_add_user = options.get("query_add_user").toString();
		this.query_get_user = options.get("query_get_user").toString();
		this.query_get_groups = options.get("query_get_groups").toString();

		boolean success = false;
		if (db_url == null) {
			logger.error("Missing option: db_url");
		} else if (db_user == null) {
			logger.error("Missing option: db_user");
		} else if (db_pass == null) {
			logger.error("Missing option: db_pass");
		} else if (db_driver == null) {
			logger.error("Missing option: db_driver");
		} else if (query_get_user == null) {
			logger.error("Missing option: query_get_user");
		} else if (query_add_user == null) {
			logger.error("Missing option: query_add_user");
		} else if (query_get_groups == null) {
			logger.error("Missing option: query_get_groups");
		} else if (providerMap.isEmpty()) {
			logger.error("No providers set up with sufficient parameter settings");
		} else {
			try {
				Class.forName(db_driver);
				conn = DriverManager.getConnection(db_url, db_user, db_pass);
				success = true;
			} catch (ClassNotFoundException | SQLException ex) {
				String error = "Could not establish database conenction";
				logger.error(error, ex.getMessage());
				logger.debug(error, ex);
			}
		}
		if (success) {
			logger.info("Oauth Login Module initialized with {} configured providers.", providerMap.size());
		} else {
			logger.error("Oauth Login Module failed to initialize.");
		}
	}

	@Override
	public boolean login() throws LoginException {
		if (conn == null) {
			throw new LoginException("Dead database connection..");
		}
		logger.debug("login module called");
		Callback[] callbacks = new Callback[2];
		callbacks[0] = new PasswordCallback("Code: ", true);
		callbacks[1] = new NameCallback("State: ");
		try {
			callbackHandler.handle(callbacks);
		} catch (IOException ex) {
			logger.error(ex.getMessage());
			logger.debug(ex.getStackTrace().toString());
			throw new LoginException(ex.getMessage());
		} catch (UnsupportedCallbackException ex) {
			logger.error(ex.getMessage());
			logger.debug(ex.getStackTrace().toString());
			return false;
		}
		String code;
		try {
			code = new String(((PasswordCallback) callbacks[0]).getPassword());
		} catch (NullPointerException npe) {
			String error = "code is not provided";
			logger.debug(error);
			throw new FailedLoginException(error);
		}
		String state = ((NameCallback) callbacks[1]).getName();
		if (state == null) {
			String error = "OAuth provided not set";
			logger.debug(error);
			throw new FailedLoginException(error);
		} else if (!providerMap.containsKey(state)) {
			String error = "OAuth provided not recognized";
			logger.debug(error);
			throw new FailedLoginException(error);
		}
		sanityCheckUserInput(code, state);
		String accessToken = getAccessToken(state, code);
		String userId = getUserId(state, accessToken);
		databaseSignIn(state, userId);

		return true;
	}

	/**
	 *
	 * @param state
	 * @param code
	 * @return
	 * @throws FailedLoginException
	 */
	private String getAccessToken(String state, String code) throws FailedLoginException {
		final String accesstokenUrl = tokenUrlMap.get(providerMap.get(state));
		final String clientID = clientIdMap.get(providerMap.get(state));
		final String secret = secretMap.get(providerMap.get(state));
		if (accesstokenUrl == null) {
			String error = "undefined logingprovider provided";
			logger.debug(error);
			throw new FailedLoginException(error);
		}

		String accessToken = postRequest(accesstokenUrl,
				new BasicNameValuePair("client_id", clientID),
				new BasicNameValuePair("code", code),
				new BasicNameValuePair("client_secret", secret));
		if (accessToken == null) {
			throw new FailedLoginException("Unable to retrieve access token");
		}

		return accessToken;
	}

	/**
	 *
	 * @param state
	 * @param accessToken
	 * @return userID from provider
	 * @throws FailedLoginException
	 */
	private String getUserId(String state, String accessToken) throws FailedLoginException {
		String userUrl = userUrlMap.get(providerMap.get(state));

		if (userUrl == null) {
			String error = "undefined logingprovider provided";
			logger.debug(error);
			throw new FailedLoginException(error);
		}

		String user_id = getRequest(userUrl, "?access_token=" + accessToken);
		if (user_id == null) {
			throw new FailedLoginException("Could not authorice user_id retrieval from access token");
		}
		return user_id;
	}

	@Override
	public boolean commit() throws LoginException {
		this.subject.getPrincipals().addAll(this.principals);
		this.logger.debug("commit");
		return true;
	}

	@Override
	public boolean abort() throws LoginException {
		this.principals.clear();
		this.logger.debug("abort");
		return true;
	}

	@Override
	public boolean logout() throws LoginException {
		this.subject.getPrincipals().removeAll(this.principals);
		this.principals.clear();
		this.logger.debug("logout");
		return true;
	}

	/**
	 * The one place a visitor to the server may alter the flow, <br/>
	 * interact with the login implementation in the oauth broker chain <br/>
	 * is in the redirection back to the login module.<br/>
	 * This is where the visitor could alter the values of the code<br/>
	 * or the state in hopes of hijacking the webserver database. <br/>
	 * However, no special characters are allowed in this sanity check. <br/>
	 * Speaking regex, it would be[a-zA-Z0-9]
	 *
	 * @param datas
	 * @throws LoginException
	 */
	private void sanityCheckUserInput(String... datas) throws LoginException {
		for (String data : datas) {
			String test_data = data.toLowerCase();
			if (test_data.contains("delete")
					|| test_data.contains("select")
					|| test_data.contains("update")
					|| test_data.contains("alter")
					|| test_data.contains("raise")
					|| test_data.contains("delete")
					|| test_data.contains("drop")) {
				throw new LoginException("User input Failed sanity check :: " + data);
			}
			for (Character c : test_data.toCharArray()) {
				int type = c.getType(c);
				if (!Character.isDigit(c) && !Character.isAlphabetic(c)) {
					throw new LoginException("Forbidden character in user data :: " + data);
				}
			}
		}
	}

	/**
	 * get accessToken using the code provided by the user
	 *
	 * @param address
	 * @param params
	 * @return
	 * @throws Exception
	 */
	private String postRequest(String address, BasicNameValuePair... params) {
		HttpClient client = new DefaultHttpClient();
		HttpPost post = new HttpPost(address);
		try {
			List<NameValuePair> nameValuePairs = new ArrayList<NameValuePair>(params.length);
			for (BasicNameValuePair paramPair : params) {
				nameValuePairs.add(paramPair);
			}
			post.setEntity(new UrlEncodedFormEntity(nameValuePairs));

			HttpResponse response = client.execute(post);
			BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
			String line = "";
			StringBuilder sb = new StringBuilder();
			while ((line = rd.readLine()) != null) {
				sb.append(line);
			}
			String string = sb.toString();

			string = string.split("access_token=")[1];
			string = string.split("&")[0];

			return string;
		} catch (IOException ex) {
			logger.error(ex.getMessage());
			logger.debug(null, ex);
		}
		return null;
	}

	/**
	 * get a user ID from a provider using the accessToken
	 *
	 * @param address
	 * @param paramString
	 * @return
	 * @throws Exception
	 */
	private String getRequest(String address, String paramString) {
		try {
			HttpClient client = new DefaultHttpClient();
			HttpGet request = new HttpGet(address + paramString);
			HttpResponse response = client.execute(request);

// Get the response
			BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));

			String line = "";
			StringBuilder sb = new StringBuilder();
			while ((line = rd.readLine()) != null) {
				sb.append(line);
			}
			String string = sb.toString();

			string = string.split("\"id\":")[1];
			string = string.split(",")[0];
			return string;
		} catch (IOException ex) {
			logger.error(ex.getMessage());
			logger.debug(null, ex);
		}
		return null;
	}

	/**
	 * assemble a parameter set ending of the request url
	 *
	 * @param paramMap
	 * @return
	 */
	private String getParamString(Map<String, String> paramMap) {
		StringBuilder sb = new StringBuilder("?");
		for (String key : paramMap.keySet()) {
			if (sb.toString().length() != 1) {
				sb.append("&");
			}
			sb.append(key).append("=").append(paramMap.get(key));
		}
		return sb.toString();
	}

	/**
	 * When you have the userID verified and all is good, tell the database
	 *
	 * @param state is used to carry the providerName
	 * @param userId unique identifier for a specific user at a specific oAuth-Provider, <br/>
	 * not necesarily unique when combining user database over several providers.
	 * @throws FailedLoginException
	 */
	private void databaseSignIn(String state, String userId) throws FailedLoginException {
		final String fix_query_get_user = query_get_user
				.replace("${provider}", state)
				.replace("${provider_user_id}", userId);
		final String fix_query_add_user = query_add_user
				.replace("${provider}", state)
				.replace("${provider_user_id}", userId);
		final String fix_query_get_groups = query_get_groups
				.replace("${provider}", state)
				.replace("${provider_user_id}", userId);
		boolean autoCommit = false;
		try {
			autoCommit = conn.getAutoCommit();
			if (autoCommit == false) {
				conn.setAutoCommit(true);
			}
			//START TRANSACTION
			conn.setAutoCommit(false);
			Integer pk = null;
			try (PreparedStatement prep = conn.prepareStatement(fix_query_get_user); ResultSet rs = prep.executeQuery()) {
				if (rs.next()) {
					pk = rs.getInt(1);
				}
			}
			//If new user, insert user
			if (pk == null) {
				try (PreparedStatement prep = conn.prepareStatement(fix_query_add_user);) {
					prep.executeUpdate();
					try (ResultSet rs = prep.getGeneratedKeys()) {
						if (rs.next()) {
							pk = rs.getInt(1);
						}
					}
				}
			}
			if (pk == null) {
				throw new FailedLoginException("Failed adding new user to local database");
			}
			//Get user roles
			try (PreparedStatement prep = conn.prepareStatement(fix_query_get_groups); ResultSet rs = prep.executeQuery()) {
				while (rs.next()) {
					principals.add(new GroupPrincipal(rs.getString(1)));
				}
			}

			principals.add(new UserPrincipal(pk.toString()));
			conn.commit();
		} catch (SQLException ex) {
			logger.error(ex.getMessage());
			logger.debug(null, ex);
		} finally {
			try {
				conn.setAutoCommit(autoCommit);
			} catch (SQLException ex) {
				logger.error(ex.getMessage());
				logger.debug(null, ex);
			}
		}
	}
}

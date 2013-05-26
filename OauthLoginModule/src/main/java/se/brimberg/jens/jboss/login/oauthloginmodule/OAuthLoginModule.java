package se.brimberg.jens.jboss.login.oauthloginmodule;

import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

/**
 * Hello world!
 *
 */
public class OAuthLoginModule implements LoginModule{

	public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
		throw new UnsupportedOperationException("Not supported yet."); 
		//To change body of generated methods, choose Tools | Templates.
	}

	public boolean login() throws LoginException {
		throw new UnsupportedOperationException("Not supported yet."); 
		//To change body of generated methods, choose Tools | Templates.
	}

	public boolean commit() throws LoginException {
		
		throw new UnsupportedOperationException("Not supported yet."); 
		//To change body of generated methods, choose Tools | Templates.
	}

	public boolean abort() throws LoginException {
		throw new UnsupportedOperationException("Not supported yet."); 
		//To change body of generated methods, choose Tools | Templates.
	}

	public boolean logout() throws LoginException {
		throw new UnsupportedOperationException("Not supported yet."); 
		//To change body of generated methods, choose Tools | Templates.
	}
}

package de.mhaug.passwordmeter;

import java.security.SecureRandom;
import java.util.Random;

import org.apache.commons.lang3.RandomStringUtils;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;

/**
 * A Web-API that takes a password as a parameter and inserts random characters
 * until the password is strong enough and then returns the result.
 * 
 * @author Martin Haug
 */
public class ImprovePassword implements Nanolet {
	private Random rand = new SecureRandom();

	@Override
	public Response serve(IHTTPSession session) {
		if (!session.getParms().containsKey("pass"))
			return new Response("Error in improving password");

		String result = improvePassword(session.getParms().get("pass"));
		return new Response(result);
	}

	/**
	 * Creates a sufficiently strong password from a weak one. Inputs which are
	 * already strong are not changed.
	 */
	String improvePassword(String pw) {
		while (!PasswordChecker.checkPassword(pw).strength.equals(PasswordStrength.STRONG)) {
			pw = RandomStringUtils.randomAlphanumeric(6).trim();
		}

		assert PasswordChecker.checkPassword(pw).strength.equals(PasswordStrength.STRONG);
		return pw;
	}
}
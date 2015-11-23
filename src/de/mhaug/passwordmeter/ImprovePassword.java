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
		if (pw.isEmpty()) {
			pw = RandomStringUtils.randomAscii(7);
		}

		while (!PasswordChecker.checkPassword(pw).strength.equals(PasswordStrength.STRONG)) {
			int idx = rand.nextInt(pw.length());
			int choice = rand.nextInt(2);
			if (choice == 0) {
				pw = pw.substring(0, idx) + RandomStringUtils.randomAlphabetic(1) + pw.substring(idx, pw.length());
			} else if (choice == 1) {
				pw = pw.substring(0, idx) + RandomStringUtils.randomNumeric(1) + pw.substring(idx, pw.length());
			}
			pw = pw.trim();
		}

		assert PasswordChecker.checkPassword(pw).strength.equals(PasswordStrength.STRONG);
		return pw;
	}
}
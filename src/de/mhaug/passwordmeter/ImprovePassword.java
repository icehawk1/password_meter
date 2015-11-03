package de.mhaug.passwordmeter;

import java.security.SecureRandom;
import java.util.Random;

import org.apache.commons.lang3.RandomStringUtils;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;

public class ImprovePassword implements Nanolet {
	private Random rand = new SecureRandom();

	@Override
	public Response serve(IHTTPSession session) {
		if (!session.getParms().containsKey("pass"))
			return new Response("Error in improving password");

		// List<PasswordComponent> components =
		// dissectPassword(session.getParms().get("pass"));
		// List<PasswordComponent> newPassword =
		// createAcceptablePassword(components);
		// return new Response(reassemble(newPassword));
		String result = temporarlyImprovePassword(session.getParms().get("pass"));
		return new Response(result);
	}

	String temporarlyImprovePassword(String pw) {
		if (pw.isEmpty()) {
			pw = RandomStringUtils.randomAscii(7);
		}

		while (!PasswordChecker.checkPassword(pw).strength.equals(PasswordStrength.STRONG)) {
			int idx = rand.nextInt(pw.length());
			int choice = rand.nextInt(3);
			if (choice == 0) {
				pw = pw.substring(0, idx) + RandomStringUtils.randomAlphabetic(1) + pw.substring(idx, pw.length());
			} else if (choice == 1) {
				pw = pw.substring(0, idx) + RandomStringUtils.randomNumeric(1) + pw.substring(idx, pw.length());
			} else if (choice == 2) {
				pw = pw.substring(0, idx) + RandomStringUtils.randomAscii(1) + pw.substring(idx, pw.length());
			}
			pw = pw.trim();
		}

		assert PasswordChecker.checkPassword(pw).strength.equals(PasswordStrength.STRONG);
		return pw;
	}
}
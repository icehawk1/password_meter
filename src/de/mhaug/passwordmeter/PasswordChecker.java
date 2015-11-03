package de.mhaug.passwordmeter;

import java.util.Arrays;

import org.passay.CharacterCharacteristicsRule;
import org.passay.CharacterRule;
import org.passay.EnglishCharacterData;
import org.passay.LengthRule;
import org.passay.PasswordData;
import org.passay.PasswordValidator;
import org.passay.UsernameRule;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;

public class PasswordChecker implements Nanolet {
	private static PasswordValidator mediumValidator = createMediumRule();
	private static PasswordValidator strongValidator = createStrongRule();

	@Override
	public Response serve(IHTTPSession session) {
		PasswordStrength strength = checkPassword(session.getParms().get("user"), session.getParms().get("pass"));
		return new Response(strength.name());
	}

	private static PasswordValidator createMediumRule() {
		CharacterCharacteristicsRule requiredAlphabets = new CharacterCharacteristicsRule();
		requiredAlphabets.setNumberOfCharacteristics(2);
		requiredAlphabets.getRules().add(new CharacterRule(EnglishCharacterData.UpperCase, 1));
		requiredAlphabets.getRules().add(new CharacterRule(EnglishCharacterData.LowerCase, 1));
		requiredAlphabets.getRules().add(new CharacterRule(EnglishCharacterData.Digit, 1));
		requiredAlphabets.getRules().add(new CharacterRule(EnglishCharacterData.Special, 1));

		return new PasswordValidator(Arrays.asList(new LengthRule(4, 20), new UsernameRule(true, true),
				requiredAlphabets));
	}

	private static PasswordValidator createStrongRule() {
		CharacterCharacteristicsRule requiredAlphabets = new CharacterCharacteristicsRule();
		requiredAlphabets.setNumberOfCharacteristics(4);
		requiredAlphabets.getRules().add(new CharacterRule(EnglishCharacterData.UpperCase, 1));
		requiredAlphabets.getRules().add(new CharacterRule(EnglishCharacterData.LowerCase, 1));
		requiredAlphabets.getRules().add(new CharacterRule(EnglishCharacterData.Digit, 1));
		requiredAlphabets.getRules().add(new CharacterRule(EnglishCharacterData.Special, 1));

		return new PasswordValidator(Arrays.asList(new LengthRule(6, 20), new UsernameRule(true, true),
				requiredAlphabets));
	}

	public static PasswordStrength checkPassword(String user, String password) {
		PasswordData pwData = new PasswordData();
		if (!user.isEmpty())
			pwData.setUsername(user);
		else
			pwData.setUsername("user");
		pwData.setPassword(password);

		boolean mediumStrength = mediumValidator.validate(pwData).isValid();
		boolean strongStrength = strongValidator.validate(pwData).isValid();

		if (mediumStrength && strongStrength)
			return PasswordStrength.STRONG;
		else if (mediumStrength && !strongStrength)
			return PasswordStrength.MEDIUM;
		else
			return PasswordStrength.WEAK;
	}

	public static PasswordStrength checkPassword(String password) {
		return checkPassword("XYZabc123", password);
	}
}

enum PasswordStrength {
	WEAK, MEDIUM, STRONG
}
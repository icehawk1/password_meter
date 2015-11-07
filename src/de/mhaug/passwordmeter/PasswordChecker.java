package de.mhaug.passwordmeter;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import org.passay.CharacterCharacteristicsRule;
import org.passay.CharacterRule;
import org.passay.EnglishCharacterData;
import org.passay.LengthRule;
import org.passay.MessageResolver;
import org.passay.PasswordData;
import org.passay.PasswordValidator;
import org.passay.PropertiesMessageResolver;
import org.passay.RuleResult;
import org.passay.UsernameRule;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;

public class PasswordChecker implements Nanolet {
	private static PasswordValidator mediumValidator = createMediumRule();
	private static PasswordValidator strongValidator = createStrongRule();

	@Override
	public Response serve(IHTTPSession session) {
		Gson gson = new Gson();
		Answer answer = checkPassword(session.getParms().get("user"), session.getParms().get("pass"));
		return new Response(gson.toJson(answer));
	}

	private static MessageResolver createMessageResolver() {
		Properties props = new Properties();
		try {
			props.load(new FileInputStream("templates/messages.properties"));
		} catch (IOException e) {
			e.printStackTrace();
		}
		MessageResolver result = new PropertiesMessageResolver(props);
		return result;
	}

	private static PasswordValidator createMediumRule() {
		CharacterCharacteristicsRule requiredAlphabets = new CharacterCharacteristicsRule();
		requiredAlphabets.setNumberOfCharacteristics(2);
		requiredAlphabets.getRules().add(new CharacterRule(EnglishCharacterData.UpperCase, 1));
		requiredAlphabets.getRules().add(new CharacterRule(EnglishCharacterData.LowerCase, 1));
		requiredAlphabets.getRules().add(new CharacterRule(EnglishCharacterData.Digit, 1));
		requiredAlphabets.getRules().add(new CharacterRule(EnglishCharacterData.Special, 1));

		return new PasswordValidator(Arrays.asList(new LengthRule(4, Integer.MAX_VALUE), new UsernameRule(true, true),
				requiredAlphabets));
	}

	private static PasswordValidator createStrongRule() {
		MessageResolver resolver = createMessageResolver();

		CharacterCharacteristicsRule requiredAlphabets = new CharacterCharacteristicsRule();
		requiredAlphabets.setNumberOfCharacteristics(4);
		requiredAlphabets.getRules().add(new CharacterRule(EnglishCharacterData.UpperCase, 1));
		requiredAlphabets.getRules().add(new CharacterRule(EnglishCharacterData.LowerCase, 1));
		requiredAlphabets.getRules().add(new CharacterRule(EnglishCharacterData.Digit, 1));
		requiredAlphabets.getRules().add(new CharacterRule(EnglishCharacterData.Special, 1));

		return new PasswordValidator(resolver, Arrays.asList(new LengthRule(6, Integer.MAX_VALUE), new UsernameRule(
				true, true), requiredAlphabets));
	}

	public static Answer checkPassword(String user, String password) {
		PasswordData pwData = new PasswordData();
		if (user != null && !user.isEmpty())
			pwData.setUsername(user);
		else
			pwData.setUsername("user");
		pwData.setPassword(password);

		RuleResult mediumResult = mediumValidator.validate(pwData);
		RuleResult strongResult = strongValidator.validate(pwData);

		Answer result = new Answer();
		if (mediumResult.isValid() && strongResult.isValid())
			result.strength = PasswordStrength.STRONG;
		else if (mediumResult.isValid() && !strongResult.isValid())
			result.strength = PasswordStrength.MEDIUM;
		else
			result.strength = PasswordStrength.WEAK;

		List<String> messages = strongValidator.getMessages(strongResult);
		if (!messages.isEmpty()) {
			// Ignore empty messages, because that are the annoying ones
			for (String msg : messages)
				if (!msg.isEmpty())
					result.message = "<br>" + msg;
		}

		return result;
	}

	public static Answer checkPassword(String password) {
		return checkPassword("XYZabc123", password);
	}
}

class Answer {
	@SerializedName("strength")
	public PasswordStrength strength = PasswordStrength.WEAK;
	// @SerializedName("Upper")
	// public boolean upper = false;
	// @SerializedName("Lower")
	// public boolean lower = false;
	// @SerializedName("Digit")
	// public boolean digit = false;
	// @SerializedName("Symbol")
	// public boolean symbol = false;
	// @SerializedName("User")
	// public boolean user = false;
	@SerializedName("message")
	public String message = "";
}

enum PasswordStrength {
	WEAK, MEDIUM, STRONG
}
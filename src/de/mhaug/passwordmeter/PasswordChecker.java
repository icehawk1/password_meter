package de.mhaug.passwordmeter;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import java.util.Random;
import java.util.Scanner;

import org.passay.CharacterCharacteristicsRule;
import org.passay.CharacterRule;
import org.passay.DictionarySubstringRule;
import org.passay.EnglishCharacterData;
import org.passay.LengthRule;
import org.passay.MessageResolver;
import org.passay.PasswordData;
import org.passay.PasswordValidator;
import org.passay.PropertiesMessageResolver;
import org.passay.RuleResult;
import org.passay.UsernameRule;
import org.passay.dictionary.ArrayWordList;
import org.passay.dictionary.WordListDictionary;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;

/**
 * A Web-API that gets a password as a parameter and categorises it into weak,
 * medium and strong passwords. It also gives hints how to improve the password.
 * 
 * @author Martin Haug
 */
public class PasswordChecker implements Nanolet {
	private static PasswordValidator mediumValidator = createMediumRule();
	private static PasswordValidator strongValidator = createStrongRule();
	private static Random rand = new Random();

	@Override
	public Response serve(IHTTPSession session) {
		Gson gson = new Gson();
		Answer answer = checkPassword(session.getParms().get("user"), session.getParms().get("pass"));
		return new Response(gson.toJson(answer));
	}

	/**
	 * Creates the component that creates the hints how to improve the password.
	 */
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

	/**
	 * Create the rule for what an ok password is.
	 */
	private static PasswordValidator createMediumRule() {
		CharacterCharacteristicsRule requiredAlphabets = new CharacterCharacteristicsRule();
		requiredAlphabets.setNumberOfCharacteristics(2);
		requiredAlphabets.getRules().add(new CharacterRule(EnglishCharacterData.UpperCase, 1));
		requiredAlphabets.getRules().add(new CharacterRule(EnglishCharacterData.LowerCase, 1));
		requiredAlphabets.getRules().add(new CharacterRule(EnglishCharacterData.Digit, 1));
		// requiredAlphabets.getRules().add(new
		// CharacterRule(EnglishCharacterData.Special, 1));

		return new PasswordValidator(Arrays.asList(new LengthRule(4, Integer.MAX_VALUE), new UsernameRule(true, true),
				requiredAlphabets));
	}

	/**
	 * Create the rule for what a strong password is.
	 */
	private static PasswordValidator createStrongRule() {
		MessageResolver resolver = createMessageResolver();

		CharacterCharacteristicsRule requiredAlphabets = new CharacterCharacteristicsRule();
		requiredAlphabets.setNumberOfCharacteristics(3);
		requiredAlphabets.getRules().add(new CharacterRule(EnglishCharacterData.UpperCase, 1));
		requiredAlphabets.getRules().add(new CharacterRule(EnglishCharacterData.LowerCase, 1));
		requiredAlphabets.getRules().add(new CharacterRule(EnglishCharacterData.Digit, 1));
		// requiredAlphabets.getRules().add(new
		// CharacterRule(EnglishCharacterData.Special, 1));

		String[] passwords = readPasswords();
		DictionarySubstringRule dictrule = new DictionarySubstringRule(new WordListDictionary(new ArrayWordList(
				passwords, false)));
		// try {
		// dictrule = new DictionarySubstringRule(new WordListDictionary(new
		// FileWordList(new RandomAccessFile(
		// new File("./templates/10k_most_common.txt"), "r"))));
		// } catch (IOException e) {
		// e.printStackTrace();
		// }
		return new PasswordValidator(resolver, Arrays.asList(new LengthRule(6, Integer.MAX_VALUE), new UsernameRule(
				true, true), requiredAlphabets, dictrule));
	}

	private static String[] readPasswords() {
		try {
			Scanner filein = new Scanner(new File("./templates/10k_most_common.txt"));
			ArrayList<String> result = new ArrayList<>();
			while (filein.hasNextLine()) {
				String line = filein.nextLine().trim();
				result.add(line);
			}
			Collections.sort(result);
			return result.toArray(new String[] {});
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			return new String[] {};
		}
	}

	/**
	 * Decides if a password is weak, medium or strong.
	 */
	public static Answer checkPassword(String user, String password) {
		// Stop erratic changes of the messages
		rand.setSeed(sum(password.toCharArray()));

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
		Collections.shuffle(messages, rand);
		if (!messages.isEmpty()) {
			// Ignore empty messages, because that are the annoying ones
			for (String msg : messages)
				if (!msg.isEmpty()) {
					result.message = msg;
					if (result.message.contains("Please insert")) {
						switch (rand.nextInt(3)) {
						case 0:
							result.message += " at the beginning";
							break;
						case 1:
							result.message += " somewhere inbetween";
							break;
						case 2:
							result.message += " at the end";
							break;
						}
					}
					result.message += ". ";
				}
		}

		return result;
	}

	public static Answer checkPassword(String password) {
		return checkPassword("XYZabc123", password);
	}

	public static long sum(char[] input) {
		if (input.length == 0)
			return 0;
		long result = 0;
		for (char i : input)
			result += i;
		return result;
	}
}

class Answer {
	@SerializedName("strength")
	public PasswordStrength strength = PasswordStrength.WEAK;
	@SerializedName("message")
	public String message = "";
}

enum PasswordStrength {
	WEAK, MEDIUM, STRONG
}
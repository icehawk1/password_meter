package de.mhaug.passwordmeter;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
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

		while (!PasswordChecker.checkPassword(pw).equals(PasswordStrength.STRONG)) {
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

		assert PasswordChecker.checkPassword(pw).equals(PasswordStrength.STRONG);
		return pw;
	}

	List<PasswordComponent> createAcceptablePassword(List<PasswordComponent> components) {
		List<PasswordComponent> result = new ArrayList<>(components);
		boolean acceptable = false;
		for (int editDistance = 1; !acceptable; editDistance++) {
			for (int i = 0; i < 100 && !acceptable; i++) {
				acceptable = isAcceptable(result);
				result = improvePassword(Collections.unmodifiableList(components), editDistance);
			}
		}
		return result;
	}

	String reassemble(List<PasswordComponent> dissectedPassword) {
		assert dissectedPassword != null;
		String result = "";
		for (PasswordComponent comp : dissectedPassword)
			result += comp.value;
		return result;
	}

	private List<PasswordComponent> improvePassword(List<PasswordComponent> components, int editDistance) {
		assert components != null;
		assert !components.isEmpty();

		List<PasswordComponent> result = new ArrayList<>(components);
		for (int i = 0; i < editDistance; i++) {
			result = makeRandomChange(result);
		}
		return result;
	}

	private List<PasswordComponent> makeRandomChange(List<PasswordComponent> components) {
		int idx = -1;
		List<PasswordComponent> result = new ArrayList<>(components);
		final ComponentType[] comptypes = ComponentType.values();
		StructureOperations[] structuretypes = StructureOperations.values();

		if (rand.nextBoolean()) {
			// Change structure
			switch (structuretypes[rand.nextInt(structuretypes.length)]) {
			case Delete:
				idx = rand.nextInt(result.size());
				if (result.size() <= 1)
					break;
				if (idx == 0 || idx == result.size() - 1)
					result.remove(idx);
				else if (!result.get(idx - 1).type.equals(result.get(idx + 1).type))
					result.remove(idx);
				break;
			case Insert:
				idx = rand.nextInt(result.size());
				ComponentType choosenType;
				do {
					choosenType = comptypes[rand.nextInt(comptypes.length)];
				} while (hasSameTypeAsNeighbours(idx, result, choosenType));
				result.add(idx, createRandomComponent(choosenType, 1));
				break;
			case Switch:
				idx = rand.nextInt(result.size());
				if (result.size() <= 1)
					break;
				else if (result.size() == 2) {
					switchComponents(result, 0, 1);
				} else {
					if (idx == 0) {
						if (!result.get(0).type.equals(result.get(2).type)) {
							switchComponents(result, idx, idx + 1);
						}
					} else if (idx == result.size()) {
						switchComponents(result, idx, idx - 1);

					} else {
						switchComponents(result, idx, idx - 1);
					}
				}
				break;
			default:
				assert false : "Unknown structure operation";
				break;
			}
		} else {
			// Change a component
			switch (ComponentOperations.values()[rand.nextInt(ComponentOperations.values().length)]) {
			case Delete:
				break;
			case Insert:
				break;
			case Substitute:
				break;
			case SwitchCase:
				break;
			default:
				assert false : "Unknown component operation";
				break;
			}
		}

		assert result != null;
		assert !result.isEmpty();
		return result;
	}

	private void switchComponents(List<PasswordComponent> result, int idx1, int idx2) {
		PasswordComponent one = result.get(idx1);
		PasswordComponent two = result.get(idx2);
		result.set(idx1, two);
		result.set(idx2, one);
	}

	private PasswordComponent createRandomComponent(ComponentType choosenType, int length) {
		switch (choosenType) {
		default:
		case Digit:
			return new PasswordComponent(choosenType, RandomStringUtils.randomNumeric(length));
		case LowercaseLetter:
			return new PasswordComponent(choosenType, RandomStringUtils.randomAlphabetic(length).toLowerCase());
		case UppercaseLetter:
			return new PasswordComponent(choosenType, RandomStringUtils.randomAlphabetic(length).toUpperCase());
		case Symbol:
			return new PasswordComponent(choosenType, RandomStringUtils.random(length, false, false));
		}
	}

	private boolean hasSameTypeAsNeighbours(int idx, List<PasswordComponent> components, ComponentType choosenType) {
		if (components.size() <= 1)
			return false;

		if (idx == 0)
			return choosenType.equals(components.get(idx + 1));
		else if (idx == components.size() - 1)
			return choosenType.equals(components.get(idx - 1));
		else
			return choosenType.equals(components.get(idx - 1)) || choosenType.equals(components.get(idx + 1));
	}

	private boolean isAcceptable(List<PasswordComponent> dissectedPassword) {
		assert dissectedPassword != null;
		return PasswordChecker.checkPassword(reassemble(dissectedPassword)).compareTo(PasswordMeter.desiredStrength) >= 0;
	}

	List<PasswordComponent> dissectPassword(String rawPassword) {
		List<PasswordComponent> result = new ArrayList<>();
		if (rawPassword == null || rawPassword.isEmpty())
			return result;

		String currentValue = rawPassword.charAt(0) + "";
		ComponentType lastType = ComponentType.getTypeOf(rawPassword.charAt(0));
		for (int i = 1; i < rawPassword.length(); i++) {
			ComponentType currentType = ComponentType.getTypeOf(rawPassword.charAt(i));
			if (currentType.equals(lastType)) {
				currentValue += rawPassword.charAt(i);
			} else {
				result.add(new PasswordComponent(lastType, currentValue));
				currentValue = rawPassword.charAt(i) + "";
				lastType = currentType;
			}
		}
		if (!currentValue.isEmpty()) {
			result.add(new PasswordComponent(lastType, currentValue));
		}

		return result;
	}

	private static enum StructureOperations {
		Insert, Delete, Switch;
	}

	private static enum ComponentOperations {
		Insert, Delete, Substitute, SwitchCase
	}
}

class PasswordComponent {
	public final ComponentType type;
	public final String value;

	public PasswordComponent(ComponentType type, String value) {
		this.type = type;
		this.value = value;
	}

	public int getLength() {
		return value.length();
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof PasswordComponent))
			return false;
		PasswordComponent other = (PasswordComponent) obj;
		return type.equals(other.type) && getLength() == other.getLength();
	}

	@Override
	public String toString() {

		return type + "(" + value + ")";
	}
}

enum ComponentType {
	Digit, Symbol, UppercaseLetter, LowercaseLetter;
	public static ComponentType getTypeOf(char character) {
		if (Character.isLowerCase(character))
			return LowercaseLetter;
		else if (Character.isUpperCase(character))
			return UppercaseLetter;
		else if (Character.isDigit(character))
			return Digit;
		else
			return Symbol;
	}
}
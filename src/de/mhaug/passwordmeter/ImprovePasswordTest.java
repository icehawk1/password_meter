package de.mhaug.passwordmeter;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class ImprovePasswordTest {
	private ImprovePassword instance;
	private Random rand;

	@Before
	public void setUp() throws Exception {
		instance = new ImprovePassword();
		rand = new Random();
	}

	// dGR0TyGK
	// Hr
	// Jp

	@Test
	public void testCreateAcceptablePassword() {
		for (int i = 0; i < 100; i++) {
			String oldPw = "";
			if (rand.nextBoolean()) {
				oldPw = RandomStringUtils.randomAlphanumeric(rand.nextInt(12));
			} else {
				oldPw = RandomStringUtils.randomAscii(rand.nextInt(12));
			}
			List<PasswordComponent> dissected = instance.dissectPassword(oldPw);
			List<PasswordComponent> created = instance.createAcceptablePassword(dissected);
			Assert.assertNotNull("Failed for: " + oldPw, created);
			String newPw = instance.reassemble(created);
			Assert.assertEquals("Failed for: " + oldPw + " after " + i + " trials", PasswordStrength.STRONG,
					PasswordChecker.checkPassword(newPw));
		}
	}

	@Test
	public void testDissectPassword() {
		String input = "Alice123!";
		List<PasswordComponent> expected = new ArrayList<>();
		expected.add(new PasswordComponent(ComponentType.UppercaseLetter, "A"));
		expected.add(new PasswordComponent(ComponentType.LowercaseLetter, "lice"));
		expected.add(new PasswordComponent(ComponentType.Digit, "123"));
		expected.add(new PasswordComponent(ComponentType.Symbol, "!"));

		List<PasswordComponent> actual = instance.dissectPassword(input);

		Assert.assertEquals(expected, actual);
	}

	@Test
	public void testDissectPassword2() {
		String input = "AKB1mbo";
		List<PasswordComponent> expected = new ArrayList<>();
		expected.add(new PasswordComponent(ComponentType.UppercaseLetter, "AKB"));
		expected.add(new PasswordComponent(ComponentType.Digit, "1"));
		expected.add(new PasswordComponent(ComponentType.LowercaseLetter, "mbo"));

		List<PasswordComponent> actual = instance.dissectPassword(input);

		Assert.assertEquals(expected, actual);
	}

	@Test
	public void testDissectPassword3() {
		String input = "A";
		List<PasswordComponent> expected = new ArrayList<>();
		expected.add(new PasswordComponent(ComponentType.UppercaseLetter, "A"));

		List<PasswordComponent> actual = instance.dissectPassword(input);

		Assert.assertEquals(expected, actual);
	}

	@Test
	public void testDissectPassword_empty() {
		String input = "";
		List<PasswordComponent> expected = new ArrayList<>();

		List<PasswordComponent> actual = instance.dissectPassword(input);

		Assert.assertEquals(expected, actual);
	}
}

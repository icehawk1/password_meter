package de.mhaug.passwordmeter;

import java.util.Random;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * A testcase for ImprovePassword
 * 
 * @author Martin Haug
 */
public class ImprovePasswordTest {
	private ImprovePassword instance;
	private Random rand;

	@Before
	public void setUp() throws Exception {
		instance = new ImprovePassword();
		rand = new Random();
	}

	@Test
	public void testCreateAcceptablePassword() {
		for (int i = 0; i < 1000; i++) {
			String oldPw = "";
			if (rand.nextBoolean()) {
				oldPw = RandomStringUtils.randomAlphanumeric(rand.nextInt(12));
			} else {
				oldPw = RandomStringUtils.randomAscii(rand.nextInt(12));
			}
			String newPw = instance.improvePassword(oldPw);
			Assert.assertEquals("Failed for: " + oldPw + " after " + i + " trials", PasswordStrength.STRONG,
					PasswordChecker.checkPassword(newPw).strength);
		}
	}
}

package de.mhaug.passwordmeter;

import java.io.File;
import java.io.IOException;
import java.util.logging.Logger;

import freemarker.template.Configuration;
import freemarker.template.TemplateExceptionHandler;

public class PasswordMeter {
	public static final Logger LOG = Logger.getLogger(PasswordMeter.class.getName());
	public static final Configuration FREEMARKER_CONFIG = new Configuration(Configuration.VERSION_2_3_23);
	public static final PasswordStrength desiredStrength = PasswordStrength.STRONG;

	public static void main(String[] args) throws IOException {
		FREEMARKER_CONFIG.setDirectoryForTemplateLoading(new File("templates"));
		FREEMARKER_CONFIG.setDefaultEncoding("UTF-8");
		FREEMARKER_CONFIG.setTemplateExceptionHandler(TemplateExceptionHandler.HTML_DEBUG_HANDLER);

		HttpServer server = new HttpServer();
		try {
			server.start();
			System.out.println("\nRunning! Point your browser to http://localhost:8080/CreateAccount \n");
			while (true)
				Thread.sleep(100);
		} catch (IOException | InterruptedException ex) {
			System.err.println("Server could not be started");
			ex.printStackTrace();
		}
	}

}

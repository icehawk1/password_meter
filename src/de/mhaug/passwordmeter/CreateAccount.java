package de.mhaug.passwordmeter;

import java.io.IOException;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import freemarker.template.Template;
import freemarker.template.TemplateException;

/**
 * Shows a window where users can select their passwords and can verify that it
 * is strong enough. The accompanying template is templates/CreateAccount.html.
 * 
 * @author Martin Haug
 */
public class CreateAccount implements Nanolet {
	private Map<String, Object> environment = new HashMap<>();

	@Override
	public Response serve(IHTTPSession session) {
		try {
			assert session.getParms().containsKey("username");
			environment.put("username", session.getParms().get("username"));

			StringWriter out = new StringWriter();
			Template template = PasswordMeter.FREEMARKER_CONFIG.getTemplate("CreateAccount.html");
			template.process(environment, out);
			out.close();
			return new Response(out.toString());
		} catch (TemplateException | IOException e) {
			e.printStackTrace();
			return new Response("Could not process template");
		}
	}
}

package de.mhaug.passwordmeter;

import java.io.IOException;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import freemarker.template.Template;
import freemarker.template.TemplateException;

public class RetypePw implements Nanolet {
	private Map<String, Object> environment = new HashMap<>();
	
	@Override
	public Response serve(IHTTPSession session) {
		try {
			assert session.getParms().containsKey("username");
			environment.put("username", session.getParms().get("username"));
			assert session.getParms().containsKey("password");
			environment.put("password", session.getParms().get("password"));

			StringWriter out = new StringWriter();
			Template template = PasswordMeter.FREEMARKER_CONFIG.getTemplate("RetypePW.html");
			template.process(environment, out);
			out.close();
			return new Response(out.toString());
		} catch (TemplateException | IOException e) {
			e.printStackTrace();
			return new Response("Could not process template");
		}
	}

}

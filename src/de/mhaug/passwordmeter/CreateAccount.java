package de.mhaug.passwordmeter;

import java.io.IOException;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import freemarker.template.Template;
import freemarker.template.TemplateException;

public class CreateAccount implements Nanolet {
	private Map<String, Object> environment = new HashMap<>();

	public CreateAccount() {
	}

	@Override
	public Response serve(IHTTPSession session) {
		try {
			StringWriter out = new StringWriter();
			Template template = PasswordMeter.FREEMARKER_CONFIG.getTemplate("CreateAccount.ftl");
			template.process(environment, out);
			out.close();
			return new Response(out.toString());
		} catch (TemplateException | IOException e) {
			e.printStackTrace();
			return new Response("Could not process template");
		}
	}
}

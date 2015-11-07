package de.mhaug.passwordmeter;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.Response.Status;

public class HttpServer extends NanoHTTPD {
	private Map<String, Nanolet> mappings = new HashMap<>();

	public HttpServer() {
		this("localhost", 8080);
	}

	public HttpServer(String hostname, int port) {
		super(hostname, port);

		mappings.put("/", new SelectUsername());
		mappings.put("index.html", new SelectUsername());
		mappings.put("SelectUsername", new SelectUsername());
		mappings.put("PasswordChecker", new PasswordChecker());
		mappings.put("Confirmation", new Confirmation());

		mappings.put("CreateAccount", new CreateAccount());
		mappings.put("ImprovePassword", new ImprovePassword());
	}

	@Override
	public Response serve(IHTTPSession session) {
		Response result = new Response("Some error occured");

		try {
			URI uri = new URI(session.getUri());
			boolean found = false;

			for (String path : mappings.keySet()) {
				if (uri.getPath().endsWith(path)) {
					Nanolet nanolet = mappings.get(path);
					result = nanolet.serve(session);
					found = true;
				}
			}

			if (!found)
				result = serveFile(uri);
		} catch (URISyntaxException e) {
			e.printStackTrace();
		}

		return result;
	}

	private Response serveFile(URI uri) {
		try {
			File requestedFile = new File(new File("."), uri.getPath());
			if (requestedFile.isFile() && requestedFile.canRead()) {
				FileInputStream fis = new FileInputStream(requestedFile);
				return new Response(Status.OK, guessMimetype(uri.getPath()), fis);
			} else if (requestedFile.isDirectory() && requestedFile.canRead()) {
				String answer = "<ul>\n";
				for (File child : requestedFile.listFiles())
					answer += "<li><a href=\"/" + child + "\">" + child + "</a>\n";
				answer += "</ul>";
				return new Response(answer);
			} else {
				return new Response("File not found: " + uri);
			}
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			return new Response("File not readable: " + uri);
		}
	}

	private String guessMimetype(String path) {
		try {
			return Files.probeContentType(Paths.get(path));
		} catch (IOException e) {
			e.printStackTrace();
			return "text/plain";
		}
	}
}

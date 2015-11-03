package de.mhaug.passwordmeter;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;

public interface Nanolet {

	public Response serve(IHTTPSession session);
}

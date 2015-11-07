package de.mhaug.passwordmeter;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;

/**
 * Classes which implement this are able to listen for HTTP requests and to
 * answer those requests. The name is a pun on servlet, as this is essentially a
 * minimal servlet.
 * 
 * @author Martin Haug
 */
public interface Nanolet {

	public Response serve(IHTTPSession session);
}

/**
 * Server.java
 *  
 * @author Anurag Jain & Calvin Siak
 * 
 * A simple FTP server using Java ServerSocket.
 * 
 * Read more at http://mrbool.com/file-transfer-between-2-computers-with-java/24516#ixzz3ZB7wUAo8   
 */ 

import java.net.*;
import java.io.*;
import java.util.*;
import java.text.*;
import javax.net.ssl.*;

public class Server { 

	public static void main (String [] args ) throws Exception { 
		System.setProperty("javax.net.ssl.keyStore", "securecam.store");
		System.setProperty("javax.net.ssl.keyStorePassword", "password");
		ServerSocket severSocket = ((SSLServerSocketFactory) SSLServerSocketFactory.getDefault()).createServerSocket(15123);
		while(true) {
			new ServerThread(severSocket.accept()).start();
		}
    
	}
}

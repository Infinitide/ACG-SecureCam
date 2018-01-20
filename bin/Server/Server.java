import java.io.*;
import java.net.*;
import java.util.*;
import javax.net.ssl.*;
import org.apache.commons.cli.*;

public class Server { 
	
	private static int LPORT = 15123;
	private static int MAXCON = 100;
	private static InetAddress LHOST;
	private static String PRIVATEKEY = "private.key";
	
	public static void main (String[] args ) throws Exception { 
		setOptions(args);
		System.setProperty("javax.net.ssl.keyStore", "securecam.store");
		System.setProperty("javax.net.ssl.keyStorePassword", "password");
		ServerSocket severSocket = ((SSLServerSocketFactory) SSLServerSocketFactory.getDefault()).createServerSocket(LPORT, MAXCON, LHOST);
		while(true) {
			new ServerThread(severSocket.accept(), PRIVATEKEY).start();
		}
    
	}
	
	private static void setOptions(String[] op) throws Exception{
		LHOST = InetAddress.getByName("127.0.0.1");
		Options options = new Options();
		
		Option help = new Option("h", "help", false, "Prints help message");
		help.setRequired(false);
		options.addOption(help);
		
		Option lport = new Option("p", "port", true, "Port which server listens on");
		lport.setRequired(false);
		options.addOption(lport);
		
		Option lhost = new Option("l", "listen", true, "Address which server listens on");
		lhost.setRequired(false);
		options.addOption(lhost);
		
		Option key = new Option("k", "key", true, "Private Key file");
		key.setRequired(false);
		options.addOption(key);
		
		CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd;
		
		try {
            cmd = parser.parse(options, op);
			
			if (cmd.hasOption("h")){
				System.out.println("SecureCam Network Server\n");
				formatter.printHelp("java Server <options>", options);
				System.exit(0);
			}
			
			if (cmd.hasOption("l")) {
				LHOST = InetAddress.getByName(cmd.getOptionValue("l"));
			}
			
			if (cmd.hasOption("p")) {
				try {
					LPORT = Integer.parseInt(cmd.getOptionValue("p"));
				} catch (NumberFormatException e) {
					System.out.println("Int Expected for -p\n");
					System.out.println("Usage: java Server <options>");
					System.out.println("Use -h to display help");
					System.exit(0);
				}
			}
			
			if (cmd.hasOption("k")) {
				PRIVATEKEY = cmd.getOptionValue("k");
			}
        } catch (ParseException e) {
            System.out.println(e.getMessage() + '\n');
			System.out.println("Usage: java Server <options>");
			System.out.println("Use -h to display help");

            System.exit(1);
        }
	}
}

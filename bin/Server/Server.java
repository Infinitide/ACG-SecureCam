import java.net.InetAddress;
import org.apache.commons.cli.*;

public class Server { 
	
	public static void main (String[] args ) throws Exception { 
		final int maxcon = 100;
		Options options = new Options();
		
		InetAddress host = InetAddress.getByName("127.0.0.1");
		Option lhost = new Option("l", "listen", true, "Address which server listens on");
		lhost.setRequired(false);
		options.addOption(lhost);
		
		int port = 15123;
		Option lport = new Option("p", "port", true, "Port which server listens on");
		lport.setRequired(false);
		options.addOption(lport);
		
		String certPath = "ca.crt";
		Option cert = new Option("c", "certificate", true, "Certificate");
		cert.setRequired(false);
		options.addOption(cert);
		
		String keyStorePath = "securecam.server.pkcs12";
		Option keyStore = new Option("ks", "keystore", true, "Key Store Path");
		keyStore.setRequired(false);
		options.addOption(keyStore);
		
		String keyStorePassword = "server";
		Option keyStorePass = new Option("kp", "keystore-password", true, "Key Store Password");
		keyStorePass.setRequired(false);
		options.addOption(keyStorePass);
		
		String aliasName = "securecam-server";
		Option alias = new Option("a", "alias", true, "Alias for cert in keystore");
		alias.setRequired(false);
		options.addOption(alias);
		
		String aliasPassword = "server";
		Option aliasPass = new Option("ap", "alias-password", true, "Alias Password for alias");
		aliasPass.setRequired(false);
		options.addOption(aliasPass);
		
		Option help = new Option("h", "help", false, "Prints help message");
		help.setRequired(false);
		options.addOption(help);
		
		CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd;
		
		try {
            cmd = parser.parse(options, args);
			
			if (cmd.hasOption("p")) {
				try {
					port = Integer.parseInt(cmd.getOptionValue("p"));
				} catch (NumberFormatException e) {
					System.out.println("Int Expected for -p\n");
					System.out.println("Usage: java Server <options>");
					System.out.println("Use -h to display help");
					System.exit(0);
				}
			}
			
			if (cmd.hasOption("l")) {
				host = InetAddress.getByName(cmd.getOptionValue("l"));
			}
			
			if (cmd.hasOption("ks")) {
				keyStorePath = cmd.getOptionValue("ks");
			}
			
			if (cmd.hasOption("kp")) {
				keyStorePassword = cmd.getOptionValue("kp");
			}
			
			if (cmd.hasOption("a")) {
				aliasName = cmd.getOptionValue("a");
			}
			
			if (cmd.hasOption("ap")) {
				aliasPassword = cmd.getOptionValue("ap");
			}
			
			if (cmd.hasOption("c")) {
				certPath = cmd.getOptionValue("c");
			}
			
			if (cmd.hasOption("h")){
				System.out.println("SecureCam Network Server\n");
				formatter.printHelp("java Server <options>", options);
				System.exit(0);
			}
			
        } catch (ParseException e) {
            System.out.println(e.getMessage() + '\n');
			System.out.println("Usage: java Server <options>");
			System.out.println("Use -h to display help");

            System.exit(1);
        }
		
		try {
			new WebCam(keyStorePath, keyStorePassword, aliasName, aliasPassword, certPath).start(host, port, maxcon);
		} catch (Exception e){
			e.printStackTrace();
		}
		
	}
	
}

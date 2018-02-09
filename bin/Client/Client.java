/**
 * Client.java
 *  
 * @author Anurag Jain & Calvin Siak
 * 
 * A simple FTP client using Java Socket.
 * 
 * Read more at http://mrbool.com/file-transfer-between-2-computers-with-java/24516#ixzz3ZB8c5M00  
 */

import java.security.*;
import java.net.*; 
import java.io.*;
import java.nio.file.*;
import org.apache.commons.cli.*;

public class Client { 
	
	private static ByteArrayOutputStream CACHE;
	private static String CACERT = "ca.crt";
	private static String HOST = "127.0.0.1";
	private static int PORT = 15123;
	private static String SAVETO = "image.jpg";
	private static Connection CONNECTION;
	
	public static void main(String [] args) throws IOException {
		Options options = new Options();
		
		
		Option sport = new Option("p", "port", true, "Port which server listens on");
		sport.setRequired(false);
		options.addOption(sport);
		
		Option shost = new Option("s", "server", true, "Address which server listens on");
		shost.setRequired(false);
		options.addOption(shost);
		
		Option help = new Option("h", "help", false, "Prints help message");
		help.setRequired(false);
		options.addOption(help);
		
		Option cert = new Option("c", "certificate", true, "Certificate");
		cert.setRequired(false);
		options.addOption(cert);
		
		Option output = new Option("o", "output", true, "File to save image to");
		output.setRequired(false);
		options.addOption(output);
		
		boolean gui = false;
		Option ogui = new Option("g", "gui", false, "Starts Client GUI");
		ogui.setRequired(false);
		options.addOption(ogui);
		
		String keyStorePath = "securecam.client.pkcs12";
		Option keyStore = new Option("ks", "keystore", true, "Key Store Path");
		keyStore.setRequired(false);
		options.addOption(keyStore);
		
		String keyStorePassword = "client";
		Option keyStorePass = new Option("kp", "keystore-password", true, "Key Store Password");
		keyStorePass.setRequired(false);
		options.addOption(keyStorePass);
		
		String aliasName = "securecam-client";
		Option alias = new Option("a", "alias", true, "Alias for cert in keystore");
		alias.setRequired(false);
		options.addOption(alias);
		
		String aliasPassword = "client";
		Option aliasPass = new Option("ap", "alias-password", true, "Alias Password for alias");
		aliasPass.setRequired(false);
		options.addOption(aliasPass);
		
		CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd;
		
		try {
            cmd = parser.parse(options, args);
			gui = cmd.hasOption("g");
			
			if (cmd.hasOption("h")){
				System.out.println("SecureCam Network Client\n");
				formatter.printHelp("java Client <options>", options);
				System.exit(0);
			}
			
			if (cmd.hasOption("s")) {
				HOST = cmd.getOptionValue("s");
				if (!HOST.matches("([0-9]{1,3}\\.){3}[0-9]{1,3}")){
					System.out.println("Invalid IP detected\n");
					System.out.println("Usage: java Server <options>");
					System.out.println("Use -h to display help");
					System.exit(0);
				}
			}
			
			if (cmd.hasOption("p")) {
				try {
					PORT = Integer.parseInt(cmd.getOptionValue("p"));
				} catch (NumberFormatException e) {
					System.out.println("Int Expected for -p\n");
					System.out.println("Usage: java Server <options>");
					System.out.println("Use -h to display help");
					System.exit(0);
				}
			}
			
			if (cmd.hasOption("c")) {
				CACERT = cmd.getOptionValue("c");
			}
			
			if (cmd.hasOption("o")) {
				SAVETO = cmd.getOptionValue("o");
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
        } catch (ParseException e) {
            System.out.println(e.getMessage() + '\n');
			System.out.println("Usage: java Server <options>");
			System.out.println("Use -h to display help");

            System.exit(1);
		}
		try {
			CONNECTION = new Connection(CACERT, keyStorePath, keyStorePassword, aliasName, aliasPassword);
		} catch (Exception e){
			e.printStackTrace();
		}
		if (gui) {
			initGui();
		} else {
			CONNECTION.start(HOST, PORT, SAVETO);
		}
	}
  
	private static void initGui() {
		try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(ClientGUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(ClientGUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(ClientGUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(ClientGUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
		
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new ClientGUI(CONNECTION, HOST, PORT, CACERT, SAVETO).setVisible(true);
            }
        });
	}
	
    
}

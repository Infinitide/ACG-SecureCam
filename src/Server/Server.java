import java.net.InetAddress;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import java.net.ServerSocket;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.security.cert.Certificate;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.ParseException;

public class Server { 
	
	private X509Certificate CACERT;
	private Certificate CERT;
	private KeyPair KEYPAIR;
	private static Logger LOG;
	
	
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
		
		Option verb = new Option("v", "verbose", false, "Verbose Output");
		verb.setRequired(false);
		options.addOption(verb);
		
		Option help = new Option("h", "help", false, "Prints help message");
		help.setRequired(false);
		options.addOption(help);
		
		CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd;
		
		try {
            cmd = parser.parse(options, args);
			LOG = new Logger(cmd.hasOption("v"));
			if (cmd.hasOption("p")) {
				try {
					port = Integer.parseInt(cmd.getOptionValue("p"));
				} catch (NumberFormatException e) {
					LOG.error("Int Expected for -p\n\nUsage: java Server <options>");
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
			LOG.error(e.getMessage() + '\n' + "Usage: java Server <options>\nUse -h to display help");
            System.exit(1);
        }
		LOG.verbose("Server Startup Initiated");
		
		try {
			new Server(keyStorePath, keyStorePassword, aliasName, aliasPassword, certPath).start(host, port, maxcon);
		} catch (Exception e){
			LOG.error("An unexpected Error Occured\n", e);
		}
		
	}
	
	/**
	 * Prepare Server for connection
	 * @param	keyStorePath				Path of keystore where sever private key is located
	 * @param	keyStorePassword			Password to keystore where server private key is located
	 * @param	aliasName					Alias of server private key
	 * @param	aliasPassword				Password of the alias of server private key
	 * @param	ca							Path where CA certificate
	 * @throws	UnrecoverableKeyException	When key cannot be retrieved
	 * @throws	FileNotFoundException		When file cannot be found
	 * @throws	KeyStoreException			When something is wrong with the keystore
	 * @param	IOException					When file cant be read
	 * @param	BoSuchAlgorithnException	When algorithm is not found
	 * @param	CertificateException		When something is wrong with the certificate
	 */
	private Server(String keyStorePath, String keyStorePassword, String aliasName, String aliasPassword, String ca) throws UnrecoverableKeyException, FileNotFoundException, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException{
		// Load CA Cert
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		FileInputStream readCa = new FileInputStream(ca);
		CACERT = (X509Certificate) cf.generateCertificate(readCa);
		readCa.close();
		
		//Load keystore using PKCS#12
		FileInputStream readKeyStore = new FileInputStream(keyStorePath);
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(readKeyStore, keyStorePassword.toCharArray());
		
		//Get private key of server from keystore
		Key key = keyStore.getKey(aliasName, aliasPassword.toCharArray());

		if (key instanceof PrivateKey){
			CERT = keyStore.getCertificate(aliasName);
			PublicKey pubkey = CERT.getPublicKey();
			KEYPAIR = new KeyPair(pubkey, (PrivateKey) key);
		} else {
			throw new UnrecoverableKeyException("Unable to obtain private key");
		}
	}
	
	/**
	 * @param	host					IP address for server to bind to
	 * @param	port					Port for server to bind to
	 * @param	maxcon					Maximum number of connections the server allows
	 * @param	CertificateException	When something is wrong with the certificate
	 */
	private void start(InetAddress host, int port, int maxcon) throws CertificateException {
		ServerSocket ssocket = null;
		try{
			ssocket = new ServerSocket(port);
			LOG.info("Server Startup successful");
			LOG.info("Waiting for client connection on " + host + ":" + port);
			if (CACERT == null) {
				LOG.error("CA Certificate Not Found");
				System.exit(1);
			}
			while (true)
				new ClientThread(ssocket.accept(), CERT, KEYPAIR, CACERT, LOG).start();
		} catch (IOException e){
			
			LOG.error("An error occurred");
			LOG.info("Server shutting down....");
		}
	
	}
}

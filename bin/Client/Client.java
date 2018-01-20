import java.io.*;
import java.net.*;
import java.util.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.net.ssl.*;
import javax.crypto.spec.*;
import org.apache.commons.cli.*;

public class Client { 

	private static ByteArrayOutputStream CACHE;
	private static String PUBLICKEY = "public.key";
	private static String SERVER = "127.0.0.1";
	private static int PORT = 15123;
	private static String SAVETO = "image.jpg";
	
	private static void cache(byte[] bytes){
		try {
			ByteArrayOutputStream baos = new ByteArrayOutputStream(bytes.length);
			baos.write(bytes, 0, bytes.length);
			CACHE = baos;
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private static boolean verifySignature(byte[] signature) throws Exception {
		Signature sig = Signature.getInstance("SHA1withRSA");
		byte[] keyBytes = Files.readAllBytes(new File(PUBLICKEY).toPath());
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		sig.initVerify(kf.generatePublic(spec));
		sig.update(CACHE.toByteArray());
		return sig.verify(signature);
	}

	    
    private static String asHex (byte buf[]) {
		//Obtain a StringBuffer object
		StringBuffer strbuf = new StringBuffer(buf.length * 2);
		int i;
        
		for (i = 0; i < buf.length; i++) {
			if (((int) buf[i] & 0xff) < 0x10)
				strbuf.append("0");
			strbuf.append(Long.toString((int) buf[i] & 0xff, 16));
		}
		// Return result string in Hexadecimal format
		return strbuf.toString();
	}
	
	public static void main(String [] args) throws Exception {
		setOptions(args);

		System.setProperty("javax.net.ssl.trustStore", "securecam.store");
		Socket socket = ((SSLSocketFactory) SSLSocketFactory.getDefault()).createSocket(SERVER, PORT);
		ObjectInputStream in = null;
		DataOutputStream dos = null;
		byte[] ehmac;
		
		try{
			//in = new DataInputStream(socket.getInputStream());
			in = new ObjectInputStream(socket.getInputStream());
			dos = new DataOutputStream(socket.getOutputStream());
			ArrayList data = (ArrayList) in.readObject();
			cache((byte[]) data.get(0));
			ehmac = (byte[]) data.get(1);
		} catch (Exception ee) {
			System.out.println("Check connection please");
			socket.close();
			return;
		}
		FileOutputStream fos = new FileOutputStream(SAVETO);
		//boolean verified = verify(ehmac);
		boolean verified = verifySignature(ehmac);
		try {
			if (verified){
				DataInputStream iin = new DataInputStream(new ByteArrayInputStream(CACHE.toByteArray()));;
				while (true)
					fos.write(iin.readByte());
			} else {
				System.out.println("Integrity Compromised. File not written");
			}
		} catch (EOFException ee) {
			dos.writeBytes("Transfer Completed");
			System.out.println("File transfer complete");
			
			dos.close();
		}
		in.close();
		fos.flush();
		fos.close();
		socket.close();
		
		// Print MD5
		MessageDigest myMD5 = null;
		try{
			myMD5 = MessageDigest.getInstance("MD5");
		} catch (Exception ee){
			
		}
		byte[] bFile = Files.readAllBytes(Paths.get(SAVETO));
		myMD5.update(bFile, 0, bFile.length);
		byte[] md = myMD5.digest();
		System.out.println("MD5 = " +  asHex(md) );
	}
	
	private static void setOptions(String[] op) throws Exception{
		Options options = new Options();
		
		Option help = new Option("h", "help", false, "Prints help message");
		help.setRequired(false);
		options.addOption(help);
		
		Option sport = new Option("p", "port", true, "Port which server listens on");
		sport.setRequired(false);
		options.addOption(sport);
		
		Option shost = new Option("s", "server", true, "Address which server listens on");
		shost.setRequired(false);
		options.addOption(shost);
		
		Option key = new Option("k", "key", true, "Public Key file");
		key.setRequired(false);
		options.addOption(key);
		
		Option output = new Option("o", "output", true, "File to save image to");
		output.setRequired(false);
		options.addOption(output);
		
		CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd;
		
		try {
            cmd = parser.parse(options, op);
			
			if (cmd.hasOption("h")){
				System.out.println("SecureCam Network Client\n");
				formatter.printHelp("java Client <options>", options);
				System.exit(0);
			}
			
			if (cmd.hasOption("s")) {
				SERVER = cmd.getOptionValue("l");
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
			
			if (cmd.hasOption("k")) {
				PUBLICKEY = cmd.getOptionValue("k");
			}
			if (cmd.hasOption("o")) {
				SAVETO = cmd.getOptionValue("o");
			}
        } catch (ParseException e) {
            System.out.println(e.getMessage() + '\n');
			System.out.println("Usage: java Server <options>");
			System.out.println("Use -h to display help");

            System.exit(1);
        }
	}
	
}

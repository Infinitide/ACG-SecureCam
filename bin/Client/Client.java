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
import javax.net.ssl.*; 
import java.io.*;
import java.nio.file.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;

public class Client { 

	private static ByteArrayOutputStream CACHE;
	
	private static void cache(byte[] bytes){
		try {
			ByteArrayOutputStream baos = new ByteArrayOutputStream(bytes.length);
				baos.write(bytes, 0, bytes.length);
				CACHE = baos;

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private static boolean verify(byte[] ehmac){
		DataInputStream in = new DataInputStream(new ByteArrayInputStream(CACHE.toByteArray()));;
		String keyFile = "key.txt";
		String encodedKey = null;

		byte[] result = null;
		try {
			FileReader fread = new FileReader(keyFile);
			BufferedReader bread = new BufferedReader(fread);
			encodedKey = bread.readLine();
			bread.close();
			
			byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
			SecretKey key = new SecretKeySpec(decodedKey, 0, decodedKey.length, "HmacSHA1"); 
			
			// Create and initialize a MAC with the key
			Mac mac = Mac.getInstance("HmacSHA1");
			mac.init(key);
			byte[] buffer = new byte[8192];
			int length;
			
			while ((length = in.read(buffer)) != -1)
				  mac.update(buffer, 0, length);
			result = mac.doFinal();
			
			System.out.println("Mac: " + asHex(result));
			//System.out.println("Expected: " + asHex(ehmac));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return Arrays.equals(result, ehmac);
	}
	
	public static void main(String [] args) throws IOException {
		String fname = "image.jpg";

		System.setProperty("javax.net.ssl.trustStore", "securecam.store");
		Socket socket = ((SSLSocketFactory) SSLSocketFactory.getDefault()).createSocket("localhost",15123);
		ObjectInputStream in = null;
		byte[] ehmac;
		try{
			//in = new DataInputStream(socket.getInputStream());
			in = new ObjectInputStream(socket.getInputStream());
			ArrayList data = (ArrayList) in.readObject();
			cache((byte[]) data.get(0));
			ehmac = (byte[]) data.get(1);
			
		} catch (Exception ee) {
			System.out.println("Check connection please");
			socket.close();
			return;
		}
		FileOutputStream fos = new FileOutputStream(fname);
		
		try {
			if (verify(ehmac)){
				DataInputStream iin = new DataInputStream(new ByteArrayInputStream(CACHE.toByteArray()));;
				while (true)
					fos.write(iin.readByte());
			} else {
				System.out.println("Integrity Compromised. File not written");
			}
			
		} catch (EOFException ee) {
			System.out.println("File transfer complete");
			in.close();
		}
		fos.flush();
		fos.close();
		socket.close();
		
		// Print MD5
		MessageDigest myMD5 = null;
		try{
			myMD5 = MessageDigest.getInstance("MD5");
		} catch (Exception ee){
			
		}
		byte[] bFile = Files.readAllBytes(Paths.get(fname));
		myMD5.update(bFile, 0, bFile.length);
		byte[] md = myMD5.digest();
		System.out.println("MD5 = " +  asHex(md) );
      
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
}

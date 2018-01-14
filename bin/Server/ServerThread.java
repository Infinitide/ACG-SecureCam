import java.net.*;
import java.io.*;
import java.util.*;
import java.text.*;
import javax.net.ssl.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class ServerThread extends Thread{
	private Socket SOCKET;
	private byte[] HMAC;
	private ByteArrayOutputStream CACHE;
	
	public ServerThread(Socket socket) {
		SOCKET = socket;
	}
	
	public void run() {
		try{
			System.out.println("Accepted connection : " + SOCKET.getRemoteSocketAddress().toString() + " <-> /127.0.0.1:15123" );

			DataOutputStream dos = new DataOutputStream(SOCKET.getOutputStream());
			
			// get the image from a webcam
			URL myimage = new URL("http://183.76.13.58:80/SnapshotJPEG?Resolution=640x480");
			DataInputStream in = null;
			try{
				in = new DataInputStream(myimage.openStream());
			} catch (Exception ee) {
				System.out.println("Check internet connection please");
				SOCKET.close();
				return;
			}
			
			DateFormat dateFormat = new SimpleDateFormat("yy/MM/dd HH:mm:ss");
			Date date = new Date();
			System.out.println("Sending image " + dateFormat.format(date));
		  
			cache(in);
			ArrayList data = new ArrayList();
			data.add(CACHE.toByteArray());
			data.add(HMAC);
			
			try{
				ObjectOutputStream oin = new ObjectOutputStream(SOCKET.getOutputStream());
				//in = new DataInputStream(new ByteArrayInputStream(CACHE.toByteArray()));
				//while (true) {
					//dos.writeByte(in.readByte());
				oin.writeObject(data);
				System.out.println("-------------- Done ----------");
				oin.close();
				//}
			} catch (Exception ee) {
				ee.printStackTrace();
			}
		  
			dos.flush();
			dos.close();
			SOCKET.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private void cache(DataInputStream in){
		try {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();

			byte[] buffer = new byte[1024];
			int len;
			while ((len = in.read(buffer)) > -1 ) {
				baos.write(buffer, 0, len);
			}
			baos.flush();
			
			CACHE = baos;
			initMac();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private void initMac() {
		DataInputStream in = new DataInputStream(new ByteArrayInputStream(CACHE.toByteArray()));;
		String keyFile = "key.txt";
		String encodedKey = null;
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
			HMAC = mac.doFinal();
			
			System.out.println("Mac: " + asHex(HMAC));
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}
	
	private String asHex (byte buf[]) {
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
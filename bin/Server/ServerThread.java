import java.io.*;
import java.net.*;
import java.util.*;
import java.text.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.net.ssl.*;
import javax.crypto.spec.*;
import java.security.spec.*;

public class ServerThread extends Thread{
	private Date START;
	private Socket SOCKET;
	private String PRIVATEKEY;
	private ByteArrayOutputStream CACHE;
	private byte[] SIGNATURE;
	
	public ServerThread(Socket socket, String pk) {
		START = new Date();
		SOCKET = socket;
		PRIVATEKEY = pk;
	}
	
	public void run() {
		try{
			System.out.println("Accepted connection : " + SOCKET.getRemoteSocketAddress().toString() + " <-> /127.0.0.1:15123" );

			DataOutputStream dos = new DataOutputStream(SOCKET.getOutputStream());
			
			// get the image from a webcam
			URL myimage = new URL("http://183.76.13.58:80/SnapshotJPEG?Resolution=640x480");
			DataInputStream in = null;
			DataInputStream din = null;
			ObjectOutputStream oon = null;
			
			try{
				in = new DataInputStream(myimage.openStream());
				din = new DataInputStream(SOCKET.getInputStream());
				oon = new ObjectOutputStream(SOCKET.getOutputStream());
			} catch (Exception ee) {
				System.out.println("Check internet connection please");
				SOCKET.close();
				return;
			}
			
			DateFormat dateFormat = new SimpleDateFormat("yy/MM/dd HH:mm:ss");
			System.out.println("Sending image " + dateFormat.format(START));
			
			cache(in);
			sign();
			ArrayList data = new ArrayList();
			data.add(CACHE.toByteArray());
			data.add(SIGNATURE);
			try{
				oon.writeObject(data);
			} catch (Exception e) {
				System.out.println("-------------- Done ----------");
			}
			
			String sta = din.readLine();
			if (sta.equals("Transfer Completed")){
				System.out.println("Handshake Completed");
			} else {
				System.out.println("Handshake Error");
			}
			
			oon.flush();
			dos.flush();
			oon.close();
			dos.close();
			din.close();
			SOCKET.close();
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private void sign() throws InvalidKeyException, Exception{
		Signature sig = Signature.getInstance("SHA1withRSA");
		byte[] keyBytes = Files.readAllBytes(new File(PRIVATEKEY).toPath());
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		sig.initSign(kf.generatePrivate(spec));
		sig.update(CACHE.toByteArray());
		SIGNATURE = sig.sign();
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
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private String asHex(byte buf[]) {
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
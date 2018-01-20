import java.io.*;
import java.net.*;
import java.util.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.net.ssl.*;
import javax.crypto.spec.*;

public class ClientConnection{
	private static int PORT;
	private static String SERVER;
	private static String PUBLICKEY;
	private static ByteArrayOutputStream CACHE;
	private static byte[] EXPSIG;
	private boolean AUTHENTIC;
	
	public ClientConnection(String server, int port, String pubkey, javax.swing.JLabel statBar) {
		SERVER = server;
		PORT = port;
		PUBLICKEY = pubkey;
		connect(statBar);
	}
	
	public byte[] getCache(){
		return CACHE.toByteArray();
	}
	
	public void save(String ouput){
		try {
			FileOutputStream fos = new FileOutputStream(ouput);
			DataInputStream in = new DataInputStream(new ByteArrayInputStream(CACHE.toByteArray()));;
			while (true)
				fos.write(in.readByte());
		} catch (EOFException ee) {
			System.out.println("File saved");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private static void cache(byte[] bytes){
		try {
			ByteArrayOutputStream baos = new ByteArrayOutputStream(bytes.length);
			baos.write(bytes, 0, bytes.length);
			CACHE = baos;
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private boolean verifySignature() throws Exception {
		Signature sig = Signature.getInstance("SHA1withRSA");
		byte[] keyBytes = Files.readAllBytes(new File(PUBLICKEY).toPath());
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		sig.initVerify(kf.generatePublic(spec));
		sig.update(CACHE.toByteArray());
		return sig.verify(EXPSIG);
	}
	
	private void connect(javax.swing.JLabel statBar){
		try {
			Socket socket = ((SSLSocketFactory) SSLSocketFactory.getDefault()).createSocket(SERVER, PORT);
			ObjectInputStream in = null;
			DataOutputStream dos = null;
			
			try{
				//in = new DataInputStream(socket.getInputStream());
				in = new ObjectInputStream(socket.getInputStream());
				dos = new DataOutputStream(socket.getOutputStream());
				ArrayList data = (ArrayList) in.readObject();
				cache((byte[]) data.get(0));
				EXPSIG = (byte[]) data.get(1);
			} catch (Exception ee) {
				statBar.setText("Check connection please");
				socket.close();
				return;
			}
			
			AUTHENTIC = verifySignature();
			if (AUTHENTIC){
				statBar.setText("File transfer complete");
				dos.writeBytes("Transfer Completed");
			} else {
				statBar.setText("Integrity Compromised.");
			}
				
			in.close();
			socket.close();
			
		} catch (Exception e){
			e.printStackTrace();
		}
		
	}
}
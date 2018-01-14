import java.net.*;
import java.io.*;
import java.util.*;
import java.text.*;
import javax.net.ssl.*;

public class ServerThread extends Thread{
	private Socket SOCKET;
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
			System.out.println("Sending image " + dateFormat.format(date) );
		  
			try{
				while (true) {
					dos.writeByte(in.readByte());
				}
			} catch (EOFException ee) {
				System.out.println("-------------- Done ----------");
				in.close();
			}
		  
			dos.flush();
			dos.close();
			SOCKET.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
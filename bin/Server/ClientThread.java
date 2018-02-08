import java.io.DataInputStream;
import java.io.ObjectOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.EOFException;
import java.util.Date;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.net.URL;
import java.net.Socket;
import java.security.KeyPair;
import java.security.Security;
import java.security.SecureRandom;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.crypto.tls.TlsUtils;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.TlsServerProtocol;
import org.bouncycastle.crypto.tls.DefaultTlsServer;
import org.bouncycastle.crypto.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.crypto.tls.TlsContext;
import org.bouncycastle.crypto.tls.TlsSignerCredentials;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.tls.DefaultTlsSignerCredentials;

import java.nio.file.*;
import java.security.MessageDigest;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ByteArrayInputStream;

public class ClientThread extends Thread {
	
	private Socket SOCKET;
	private java.security.cert.Certificate SERVERCERT;
	private KeyPair KEYPAIR;
	private ByteArrayOutputStream CACHE;
	
	public ClientThread(Socket socket, java.security.cert.Certificate c, KeyPair kp){
		SOCKET = socket;
		SERVERCERT = c;
		KEYPAIR = kp;
	}
	
	public void run(){
		Security.addProvider(new BouncyCastleProvider());
		try{
			Certificate cert = Certificate.getInstance(ASN1TaggedObject.fromByteArray(SERVERCERT.getEncoded()));
			// Start TLS handshake
			TlsServerProtocol proto = new TlsServerProtocol(SOCKET.getInputStream(), SOCKET.getOutputStream(), new SecureRandom());
			DefaultTlsServer server = new DefaultTlsServer() {
				protected ProtocolVersion getMaximumVersion(){
					return ProtocolVersion.TLSv12;
				}
				
				protected TlsSignerCredentials getRSASignerCredentials() throws IOException {
							SignatureAndHashAlgorithm signatureAndHashAlgorithm = (SignatureAndHashAlgorithm) TlsUtils.getDefaultRSASignatureAlgorithms().get(0);
							return new DefaultTlsSignerCredentials((TlsContext)context,
								new org.bouncycastle.crypto.tls.Certificate(new org.bouncycastle.asn1.x509.Certificate[]{cert}),
								PrivateKeyFactory.createKey(KEYPAIR.getPrivate().getEncoded()),
								signatureAndHashAlgorithm);
						}
			};
			proto.accept(server);
			
			// Begin data transfer
			System.out.println("Accepted connection : " + SOCKET.getRemoteSocketAddress().toString() + " <-> /127.0.0.1:15123" );
			
			URL myimage = new URL("http://183.76.13.58:80/SnapshotJPEG?Resolution=640x480");
			DataInputStream in = null;
			try{
				in = new DataInputStream(myimage.openStream());
			} catch (Exception ee) {
				System.out.println("Check internet connection please");
				SOCKET.close();
				return;
			}
			cache(in);
			in.close();
			
			ObjectOutputStream oos = new ObjectOutputStream(proto.getOutputStream());
			//ObjectInputStream ois = new ObjectInputStream(proto.getInputStream());
			
			DateFormat dateFormat = new SimpleDateFormat("yy/MM/dd HH:mm:ss");
			Date date = new Date();
			System.out.println("Sending image " + dateFormat.format(date) );
		  
			try{
				oos.writeObject(CACHE.toByteArray());
			} catch (EOFException ee) {
				System.out.println("-------------- Done ----------");
			}
			oos.flush();
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
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
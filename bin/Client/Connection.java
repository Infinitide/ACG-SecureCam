import java.net.Socket;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.EOFException;
import java.io.FileNotFoundException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Security;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.DefaultTlsClient;
import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.crypto.tls.TlsClientProtocol;
import org.bouncycastle.crypto.tls.ServerOnlyTlsAuthentication;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class Connection {
	private String HOST;
	private int PORT;
	private X509Certificate CACERT;
	private Socket SOCKET;
	private ByteArrayOutputStream CACHE;
	private javax.swing.JLabel STATBAR;
	
	public Connection(String host, int port, String ca, javax.swing.JLabel statBar) throws CertificateException, FileNotFoundException, IOException{
		HOST = host;
		PORT = port;
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		FileInputStream readCa = new FileInputStream(ca);
		CACERT = (X509Certificate) cf.generateCertificate(readCa);
		readCa.close();
		STATBAR = statBar;
		start();
	}
	
	public Connection(String host, int port, String ca) throws CertificateException, FileNotFoundException, IOException{
		HOST = host;
		PORT = port;
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		FileInputStream readCa = new FileInputStream(ca);
		CACERT = (X509Certificate) cf.generateCertificate(readCa);
		readCa.close();
	}
	
	public void start(){
		Security.addProvider(new BouncyCastleProvider());
		
		try{
			SOCKET = new Socket(HOST, PORT);
			// Create TLS Client Protocol
			TlsClientProtocol cproto = new TlsClientProtocol(SOCKET.getInputStream(), SOCKET.getOutputStream(), new SecureRandom());
			
			// Initialise TLS Connection
			cproto.connect(new DefaultTlsClient() {
				public TlsAuthentication getAuthentication() throws IOException{
					return new ServerOnlyTlsAuthentication() {
						public void notifyServerCertificate(Certificate serverCert) throws IOException {
							try {
								X509Certificate servCert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(serverCert.getCertificateList()[0].getEncoded()));
								//verifyCert(servCert);
							} catch (Exception e){
								System.out.println("Unable to verify server's certificate: " + e);
								e.printStackTrace();
							}
						};
					};
				}
			});
			
			/* Get TLS connection socket stream
			 * Traffic using this stream will be encrypted
			 * and decrypted automatically
			 */
			 
			ObjectInputStream in = new ObjectInputStream(cproto.getInputStream());
			
			try {
				cache((byte[]) in.readObject());
			} catch (Exception e) {
				e.printStackTrace();
			}
		} catch (Exception e){
			e.printStackTrace();
		}
	}
	
	private void cache(byte[] bytes){
		try {
			ByteArrayOutputStream baos = new ByteArrayOutputStream(bytes.length);
			baos.write(bytes, 0, bytes.length);
			CACHE = baos;
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	
	public void save(String output, javax.swing.JLabel statBar){
		save(output);
		statBar.setText("File saved to " + output);
	}
	
	public void save(String fname) {
		try{
			FileOutputStream fos = new FileOutputStream(fname);
			DataInputStream in = new DataInputStream(new ByteArrayInputStream(CACHE.toByteArray()));
			try {
				while (true)
					fos.write(in.readByte());
			} catch (EOFException ee) {
				System.out.println("File transfer complete");
				in.close();
			}
			fos.flush();
			fos.close();
			SOCKET.close();
			
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
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public byte[] getCache(){
		return CACHE.toByteArray();
	}
	
	private void verifyCert(X509Certificate servCert) throws CertificateException{
		if (CACERT == null) 
			throw new IllegalArgumentException("CA Certificate Not Found");
		if (servCert == null) 
			throw new IllegalArgumentException("Server Certificate Not Found");
		
		if (!CACERT.equals(servCert)){
			try{
				servCert.verify(CACERT.getPublicKey());
			} catch (Exception e) {
				throw new CertificateException("Server Cerficate not Trusted");
			}
		}
		
		try {
			servCert.checkValidity();
		} catch (Exception e) {
			throw new CertificateException("Server Certificate is expired");
		}
	}
	
	/**
	 * Converts a byte array to hex
	 * @param buf[] Byte array which is to be converted to hex String
	 */
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
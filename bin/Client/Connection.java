import javax.swing.JLabel;
import java.net.Socket;
import java.net.ConnectException;
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
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Security;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.UnrecoverableKeyException;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.crypto.tls.TlsUtils;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.TlsCredentials;
import org.bouncycastle.crypto.tls.DefaultTlsClient;
import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.crypto.tls.TlsClientProtocol;
import org.bouncycastle.crypto.tls.CertificateRequest;
import org.bouncycastle.crypto.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.crypto.tls.TlsNoCloseNotifyException;
import org.bouncycastle.crypto.tls.DefaultTlsSignerCredentials;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Connection {
	private X509Certificate CACERT;
	private Socket SOCKET;
	private ByteArrayOutputStream CACHE;
	private JLabel STATBAR = null;
	private java.security.cert.Certificate CLIENTCERT;
	private KeyPair KEYPAIR;
	private boolean VALID = false;
	
	public Connection(String ca, String keyStorePath, String keyStorePassword, String aliasName, String aliasPassword) throws UnrecoverableKeyException, FileNotFoundException, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException{
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
			CLIENTCERT = keyStore.getCertificate(aliasName);
			PublicKey pubkey = CLIENTCERT.getPublicKey();
			KEYPAIR = new KeyPair(pubkey, (PrivateKey) key);
		} else {
			throw new UnrecoverableKeyException("Unable to obtain private key");
		}
	}
	
	public void start(String host, int port, String output, JLabel statBar){
		STATBAR = statBar;
		start(host, port, output);
	}
	
	public void start(String host, int port, String output){
		Security.addProvider(new BouncyCastleProvider());
		try{
			SOCKET = new Socket(host, port);
			org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate.getInstance(ASN1TaggedObject.fromByteArray(CLIENTCERT.getEncoded()));
			// Create TLS Client Protocol
			TlsClientProtocol cproto = new TlsClientProtocol(SOCKET.getInputStream(), SOCKET.getOutputStream(), new SecureRandom());
			
			// Initialise TLS Connection
			cproto.connect(new DefaultTlsClient() {
				public TlsAuthentication getAuthentication() throws IOException{
					return new TlsAuthentication() {
						public void notifyServerCertificate(Certificate serverCert) throws IOException {
							try {
								X509Certificate servCert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(serverCert.getCertificateList()[0].getEncoded()));
								verifyCert(servCert);
							} catch (Exception e){
								System.out.println("Unable to verify server's certificate");
							}
						};
						
						public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) throws IOException{
							SignatureAndHashAlgorithm signatureAndHashAlgorithm = (SignatureAndHashAlgorithm) TlsUtils.getDefaultRSASignatureAlgorithms().get(0);
							return new DefaultTlsSignerCredentials(
								context,
								new org.bouncycastle.crypto.tls.Certificate(new org.bouncycastle.asn1.x509.Certificate[]{cert}),
								PrivateKeyFactory.createKey(KEYPAIR.getPrivate().getEncoded()),
								signatureAndHashAlgorithm
							);
						};
						
					};
				}
			});
			
			if (!VALID)
				close(1);
			/* Get TLS connection socket stream
			 * Traffic using this stream will be encrypted
			 * and decrypted automatically
			 */
			 
			DataInputStream in = new DataInputStream(cproto.getInputStream());
			cache(in);
			System.out.println("File transfer complete");
			
			if (STATBAR == null)
				save(output);
		} catch (TlsNoCloseNotifyException e) {
			String err = "Server closed connection";
			System.out.println(err);
			if (STATBAR != null)
				STATBAR.setText(err);
			System.exit(1);
		} catch (ConnectException e) {
			String err = "Unable to connect to server";
			System.out.println(err);
			if (STATBAR != null)
				STATBAR.setText(err);
			System.exit(1);
		} catch (Exception e){
			e.printStackTrace();
		}
	}
	
	public void save(String fname) {
		try{
			FileOutputStream fos = new FileOutputStream(fname);
			DataInputStream in = new DataInputStream(new ByteArrayInputStream(CACHE.toByteArray()));
			try {
				while (true)
					fos.write(in.readByte());
			} catch (EOFException ee) {
				System.out.println("File saved!");
				in.close();
			}
			fos.flush();
			fos.close();
			close(0);
			
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
			
			if STATBAR != null
				STATBAR.setText("File saved to " + output);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	private void verifyCert(X509Certificate servCert) throws CertificateException{
		boolean ca = false;
		boolean valid = false;
		
		if (CACERT == null) 
			throw new IllegalArgumentException("CA Certificate Not Found");
		if (servCert == null)
			throw new IllegalArgumentException("Server Certificate Not Found");
		
		if (!CACERT.equals(servCert)){
			try{
				servCert.verify(CACERT.getPublicKey());
				ca = true;
			} catch (Exception e) {
				System.out.println("Server Certificate not Trusted");
			}
		}
		
		try {
			servCert.checkValidity();
			valid = true;
		} catch (Exception e) {
			System.out.println("Server Certificate is expired");
		}
		VALID = ca && valid;
	}
	
	private void close(int exitCd){
		try {
			if (CACHE != null)
				CACHE.flush();
			SOCKET.close();
			if (exitCd != 0)
				System.exit(exitCd);
		} catch (IOException e){
			e.printStackTrace();
		}
	}
	
	private void cache(DataInputStream in){
		try {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			byte[] buffer = new byte[1024];
			int len;
			while ((len = in.read(buffer)) > -1 )
				baos.write(buffer, 0, len);
			baos.flush();
			CACHE = baos;
		} catch (Exception e) {
			System.out.println("Unable to cache input");
		}
	}
	
	public byte[] getCache(){
		return CACHE.toByteArray();
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
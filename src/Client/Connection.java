import java.net.Socket;
import java.net.SocketException;
import java.util.Iterator;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
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
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import javax.swing.JLabel;
import javax.imageio.ImageIO;
import javax.imageio.ImageReader;
import javax.imageio.stream.ImageInputStream;
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
	private Logger LOG;
	
	/**
	 * Initialise Connection
	 * @param	ca							Path to CA certificate
	 * @param	keyStorePath				Path of keystore where sever private key is located
	 * @param	keyStorePassword			Password to keystore where server private key is located
	 * @param	aliasName					Alias of server private key
	 * @param	aliasPassword				Password of the alias of server private key
	 * @param	log							Logger used for formating output
	 * @throws	UnrecoverableKeyException	When key cannot be retrieved
	 * @throws	FileNotFoundException		When file cannot be found
	 * @throws	KeyStoreException			When something is wrong with the keystore
	 * @param	IOException					When file cant be read
	 * @param	BoSuchAlgorithnException	When algorithm is not found
	 * @param	CertificateException		When something is wrong with the certificate
	 */
	public Connection(String ca, String keyStorePath, String keyStorePassword, String aliasName, String aliasPassword, Logger log) throws UnrecoverableKeyException, FileNotFoundException, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException{
		LOG = log;
		
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
	
	/**
	 * Start Connection
	 * @param	host	Server IP address
	 * @param	port	Server Port
	 * @param	statBar	Status Bar to display status message for GUI
	 */
	public void start(String host, int port, JLabel statBar){
		STATBAR = statBar;
		start(host, port, (String) null);
	}
	
	/**
	 * Start Connection
	 * @param	host	Server IP address
	 * @param	port	Server Port
	 * @param	output	File to save image to
	 */
	public void start(String host, int port, String output){
		LOG.info("Connecting to server at " + host + ':' + port);
		LOG.verbose("Initiating TLS Handshake with server");
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
								LOG.error("Unable to verify server's certificate");
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
			
			// Closes connection if certificate is invalid
			if (!VALID)
				close(1);
			
			LOG.verbose("TLS Handshake successful");
			LOG.info("Retrieving image from Server");
			
			/*
			 * Get TLS connection socket stream
			 * Traffic using this stream will be encrypted and decrypted automatically
			 */
			DataInputStream in = new DataInputStream(cproto.getInputStream());
			cache(in);
			
			// Save image if output is not null
			// Output will be null if GUI is initialised
			if (output != null)
				save(output);
		} catch (SocketException e) {
			String err = "Failed to connect to server";
			LOG.error(err);
			if (STATBAR != null)
				STATBAR.setText(err);
		} catch (TlsNoCloseNotifyException e) {
			String err = "Server closed connection";
			LOG.error(err);
			if (STATBAR != null)
				STATBAR.setText(err);
			System.exit(1);
		} catch (Exception e){
			LOG.error("An error occurred");
			LOG.info("Contact your administrator");
		}
	}
	
	/**
	 * Save image from cache to file
	 * @param	fname	File name to save image to
	 */
	public void save(String fname) {
		if (CACHE == null)
			return;
		try{
			LOG.verbose("Saving Image to File");
			FileOutputStream fos = new FileOutputStream(fname);
			DataInputStream in = new DataInputStream(new ByteArrayInputStream(CACHE.toByteArray()));
			try {
				while (true)
					fos.write(in.readByte());
			} catch (EOFException ee) {
				LOG.verbose("Image Saved to file : " + fname);
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
				LOG.error("An Unexpected error occurred");
			}
			LOG.verbose("Computing MD5 Checksum");
			byte[] bFile = Files.readAllBytes(Paths.get(fname));
			myMD5.update(bFile, 0, bFile.length);
			byte[] md = myMD5.digest();
			LOG.info("MD5 checksum : " +  asHex(md));
			if (STATBAR != null)
				STATBAR.setText("File saved to " + fname + '(' + asHex(md) + ')');
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Verifies Server Certificate
	 * @param  	servCert				Server Certificate to verify
	 * @throws	CertificateException	When something is wrong with the certificate
	 */
	private void verifyCert(X509Certificate servCert) throws CertificateException{
		boolean ca = false;
		boolean valid = false;
		LOG.verbose("Verifying Server Certificate");
		
		if (servCert == null)
			throw new IllegalArgumentException("Server Certificate Not Found");
		
		if (!CACERT.equals(servCert)){
			try{
				servCert.verify(CACERT.getPublicKey());
				ca = true;
			} catch (Exception e) {
				LOG.error("Server Certificate not Trusted");
			}
		}
		
		try {
			servCert.checkValidity();
			valid = true;
		} catch (Exception e) {
			LOG.error("Server Certificate is expired");
		}
		VALID = ca && valid;
	}
	
	/**
	 * Close connection with server
	 * @param	exitCd	exitCd
	 */
	private void close(int exitCd){
		if (exitCd == 1)
			LOG.error("Server identity not verified");
		if (exitCd == 2)
			LOG.error("Image corrupted");
		try {
			if (CACHE != null)
				CACHE.flush();
			SOCKET.close();
			LOG.verbose("Connection with server closed");
			
			// Stops program if exitCd is not 0
			if (exitCd != 0)
				System.exit(1);
		} catch (IOException e){
			LOG.error("Unexpected Exception ", e);
			e.printStackTrace();
		}
	}
	
	/**
	 * Cache and verify image received from server
	 * @param	in	DataInputStream containing the image from the server
	 */
	private void cache(DataInputStream in){
		LOG.verbose("Caching Image");
		try {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			byte[] buffer = new byte[1024];
			int len;
			while ((len = in.read(buffer)) > -1 )
				baos.write(buffer, 0, len);
			baos.flush();
			CACHE = baos;
			LOG.verbose("Verifying received image");
			
			ImageInputStream imageStream = ImageIO.createImageInputStream(new BufferedInputStream(new ByteArrayInputStream(CACHE.toByteArray())));
			Iterator<ImageReader> readers = ImageIO.getImageReaders(imageStream);
			ImageReader reader = null;
			if (!readers.hasNext()) {
				  imageStream.close();
				  return;
			} else {
				reader = readers.next();
			}
			String formatName = reader.getFormatName();
			if (!formatName.equalsIgnoreCase("jpeg")) 
				close(2);
			LOG.verbose("Image Verified");
		} catch (Exception e) {
			LOG.error("Unable to cache input", e);
		}
	}
	
	/**
	 * Retrieves cache
	 * @return cache in byte array
	 */
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
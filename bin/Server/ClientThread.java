import java.net.URL;
import java.net.Socket;
import java.net.SocketException;
import java.util.Vector;
import java.io.FileInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.ObjectOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.EOFException;
import java.io.FileNotFoundException;
import java.security.KeyPair;
import java.security.Security;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.crypto.tls.TlsUtils;
import org.bouncycastle.crypto.tls.TlsContext;
import org.bouncycastle.tls.ClientCertificateType;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.DefaultTlsServer;
import org.bouncycastle.crypto.tls.TlsServerProtocol;
import org.bouncycastle.crypto.tls.CertificateRequest;
import org.bouncycastle.crypto.tls.TlsSignerCredentials;
import org.bouncycastle.crypto.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.tls.DefaultTlsSignerCredentials;

public class ClientThread extends Thread implements Runnable{
	
	private Socket SOCKET;
	private java.security.cert.Certificate SERVERCERT;
	private KeyPair KEYPAIR;
	private ByteArrayOutputStream CACHE;
	private X509Certificate CACERT;
	private boolean VALID;
	private Logger LOG;
	private String REMOTE;
	
	public ClientThread(Socket socket, java.security.cert.Certificate c, KeyPair kp, X509Certificate cacert, Logger log) throws CertificateException, FileNotFoundException, IOException{
		SOCKET = socket;
		SERVERCERT = c;
		KEYPAIR = kp;
		CACERT = cacert;
		LOG = log;
		REMOTE = SOCKET.getRemoteSocketAddress().toString();
		LOG.verbose("Initialising connection with " + REMOTE);
	}
	
	public void run(){
		Security.addProvider(new BouncyCastleProvider());
		try{
			Certificate cert = Certificate.getInstance(ASN1TaggedObject.fromByteArray(SERVERCERT.getEncoded()));
			
			// Start TLS handshake
			TlsServerProtocol proto = new TlsServerProtocol(SOCKET.getInputStream(), SOCKET.getOutputStream(), new SecureRandom());
			
			proto.accept(new DefaultTlsServer() {
				protected ProtocolVersion getMaximumVersion(){
					return ProtocolVersion.TLSv12;
				}
				
				protected TlsSignerCredentials getRSASignerCredentials() throws IOException {
					SignatureAndHashAlgorithm signatureAndHashAlgorithm = (SignatureAndHashAlgorithm) TlsUtils.getDefaultRSASignatureAlgorithms().get(0);
					return new DefaultTlsSignerCredentials(
						(TlsContext) context,
						new org.bouncycastle.crypto.tls.Certificate(new Certificate[]{cert}),
						PrivateKeyFactory.createKey(KEYPAIR.getPrivate().getEncoded()),
						signatureAndHashAlgorithm
					);
				}
				
				public CertificateRequest getCertificateRequest() {
					try {
						Vector<Object> certs = new Vector<Object>();
						
						Certificate cacert = Certificate.getInstance(CACERT.getEncoded());
						
						certs.addElement(cacert.getSubject());
						
						return new CertificateRequest(
							new short[] {ClientCertificateType.rsa_sign}, 
							TlsUtils.getDefaultRSASignatureAlgorithms(), 
							certs
						);
					} catch (Exception e) {
						LOG.error(REMOTE, e);
						return null;
					}
				}
				
				public void notifyClientCertificate(org.bouncycastle.crypto.tls.Certificate clientCert) throws IOException{
					try {
						X509Certificate cliCert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(clientCert.getCertificateList()[0].getEncoded()));
						verifyCert(cliCert);
					} catch (CertificateException e) {
						LOG.warn("Unable to verify Client certificate for " + REMOTE);
					}
				}
				
			});
			
			if (!VALID){
				close();
				return;
			}
			LOG.verbose("Connection established with " + REMOTE);
			LOG.verbose("Retrieving Image");
			
			// Begin data transfer
			URL myimage = new URL("http://183.76.13.58:80/SnapshotJPEG?Resolution=640x480");
			DataInputStream in = null;
			try{
				in = new DataInputStream(myimage.openStream());
			} catch (Exception ee) {
				LOG.error("Unable to retrieve image");
				LOG.error("Check Internet Connection");
				SOCKET.close();
				return;
			}
			
			DataOutputStream dos = new DataOutputStream(proto.getOutputStream());
			LOG.verbose("Sending image to " + REMOTE);
			try{
				while (true)
					dos.writeByte(in.readByte());
			} catch (EOFException ee) {
				in.close();
				dos.flush();
				dos.close();
				LOG.verbose("Image send to " + REMOTE + " successful");
			}
			close();
			
		} catch (SocketException e){
			LOG.verbose("Client Closed Connection");
			close();
		} catch (Exception e) {
			LOG.error("Unexpected Exception", e);
		}
	}
	
	private void close(){
		try {
			if (CACHE != null)
				CACHE.flush();
			SOCKET.close();
			LOG.verbose("Connection with " + REMOTE + " closed");
		} catch (IOException e){
			System.exit(1);
		}
	}
	
	private void verifyCert(X509Certificate clientCert) {
		boolean ca = false;
		boolean valid = false;
		
		if (clientCert == null) 
			LOG.warn("Client Certificate Not Found for connection : " + REMOTE);
		
		if (!CACERT.equals(clientCert)){
			try{
				clientCert.verify(CACERT.getPublicKey());
				ca = true;
			} catch (Exception e) {
				LOG.warn(REMOTE + " Client Certificate not Trusted");
			}
		}
		
		try {
			clientCert.checkValidity();
			valid = true;
		} catch (Exception e) {
			LOG.warn(REMOTE + " Client Certificate is expired");
		}
		
		VALID = ca && valid;
	}
}
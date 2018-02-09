import java.net.InetAddress;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Security;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import java.net.ServerSocket;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.security.cert.Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class WebCam{
	
	private X509Certificate CACERT;
	private Certificate CERT;
	private KeyPair KEYPAIR;
	
	protected WebCam(String keyStorePath, String keyStorePassword, String aliasName, String aliasPassword, String ca) throws UnrecoverableKeyException, FileNotFoundException, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException{
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
			CERT = keyStore.getCertificate(aliasName);
			PublicKey pubkey = CERT.getPublicKey();
			KEYPAIR = new KeyPair(pubkey, (PrivateKey) key);
		} else {
			throw new UnrecoverableKeyException("Unable to obtain private key");
		}
	}
	
	protected void start(InetAddress host, int port, int maxcon) throws CertificateException {
		try{
			ServerSocket ssocket = new ServerSocket(port);
			while (true){
				new ClientThread(ssocket.accept(), CERT, KEYPAIR, CACERT).start();
			}
		} catch (IOException e){
			e.printStackTrace();
		}
	
	}
}
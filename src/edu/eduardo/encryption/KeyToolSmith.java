package edu.eduardo.encryption;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CRL;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import edu.eduardo.encryption.exceptions.CertificateCAVerificationException;

/**
 * @author Eduardo Amorim
 *
 */
public class KeyToolSmith {

	private static final String STORE_FOLDER = "lib/security/".replace("/", File.separator);

	private static final String KEYSTORE_TYPE = "pkcs12";

	public static KeyStore createKeyStore(String password, String keyStoreName) {
		KeyStore ks = null;
		try {
			ks = KeyStore.getInstance(KEYSTORE_TYPE);
			char[] pwdArray = password.toCharArray();
			ks.load(null, pwdArray);
			try (FileOutputStream fos = new FileOutputStream(STORE_FOLDER.concat(keyStoreName))) {
				ks.store(fos, pwdArray);
			}
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			e.printStackTrace();
		}
		return ks;
	}

	public static KeyStore loadKeyStore(String password, String keyStoreName) {
		KeyStore ks = null;
		try {
			try {
				ks = KeyStore.getInstance(KEYSTORE_TYPE, "BC");
			} catch (NoSuchProviderException e) {
				e.printStackTrace();
			}
			try (FileInputStream in = new FileInputStream(STORE_FOLDER.concat(keyStoreName))) {
				ks.load(in, password.toCharArray());
			}
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			e.printStackTrace();
		}
		return ks;
	}

	/**
	 * @param ks           the KeyStore to store the SecretKey
	 * @param storePwd     the password for accessing the KeyStore
	 * @param keyStoreName the name of the KeyStore
	 * @param entryPwd     the password to protect the SecretKey
	 * @param alias        the alias entry
	 * @param sKey         the SecretKey
	 * @return true is successful
	 */
	public static boolean storeSecretKey(KeyStore ks, String storePwd, String keyStoreName, String entryPwd,
			String alias, SecretKey sKey) {
		KeyStore.SecretKeyEntry secret = new KeyStore.SecretKeyEntry(sKey);
		KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(entryPwd.toCharArray());
		try {
			ks.setEntry(alias, secret, protParam);
			try (FileOutputStream fos = new FileOutputStream(STORE_FOLDER.concat(keyStoreName))) {
				ks.store(fos, storePwd.toCharArray());
			}
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

	public static boolean updateSecretKey(KeyStore ks, String storePwd, String keyStoreName, String entryPwd,
			String alias, SecretKey newSecretKey) {
		return storeSecretKey(ks, storePwd, keyStoreName, entryPwd, alias, newSecretKey);
	}

	/**
	 * @param ks       the KeyStore to get the SecretKey
	 * @param password the protection password of SecretKey
	 * @param alias    the alias entry
	 * @return the SecretKey
	 */
	public static SecretKey getSecretKey(KeyStore ks, String password, String alias) {
		SecretKey sk = null;
		KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(password.toCharArray());
		try {
			KeyStore.SecretKeyEntry skEntry = (KeyStore.SecretKeyEntry) ks.getEntry(alias, protParam);
			sk = skEntry.getSecretKey();
		} catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
			e.printStackTrace();
		}
		return sk;
	}

	public static boolean storePrivateKey(KeyStore ks, String password, String alias, PrivateKey pKey, String entryPwd,
			X509Certificate[] certificateChain) {
		try {
			ks.setKeyEntry(alias, pKey, entryPwd.toCharArray(), certificateChain);
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

	public static boolean updatePrivateKey(KeyStore ks, String password, String alias, PrivateKey newPrivateKey,
			String entryPwd, X509Certificate[] certificateChain) {
		return storePrivateKey(ks, password, alias, newPrivateKey, entryPwd, certificateChain);
	}

	public static boolean storeTrustedCertificate(KeyStore ks, String alias, X509Certificate trustedCertificate) {
		try {
			ks.setCertificateEntry(alias, trustedCertificate);
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

	public static boolean updateTrustedCertificate1(KeyStore ks, String alias, X509Certificate newTrustedCertificate) {
		return storeTrustedCertificate(ks, alias, newTrustedCertificate);
	}

	public static PKIXCertPathValidatorResult verifyChainCertificates1(KeyStore ks, Collection<? extends CRL> crls,
			X509Certificate cert, List<X509Certificate> certs) throws CertificateException, KeyStoreException,
			InvalidAlgorithmParameterException, NoSuchAlgorithmException, CertPathValidatorException {
		PKIXCertPathValidatorResult result = null;
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
//			List<X509Certificate> certs = Arrays.asList(certificateChain);
		CertPath certPath = cf.generateCertPath(certs);

		PKIXParameters params = new PKIXParameters(ks);
		params.setRevocationEnabled(false); // to avoid exception on empty CRL (for now)

		CertPathValidator validator = CertPathValidator.getInstance("PKIX");
		result = (PKIXCertPathValidatorResult) validator.validate(certPath, params);
		return result;
	}

	public static PKIXCertPathBuilderResult verifyChainCertificates2(KeyStore ks, Collection<? extends CRL> crls,
			X509Certificate cert, Collection<X509Certificate> certs)
			throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException,
			InvalidAlgorithmParameterException, CertPathBuilderException, CertificateCAVerificationException {
		PKIXCertPathBuilderResult result = null;
		X509CertSelector selector = new X509CertSelector();
		selector.setCertificate(cert);

		Set<TrustAnchor> trustedRootCerts = new HashSet<>();
		Set<X509Certificate> intermediateCerts = new HashSet<>();
		for (X509Certificate crt : certs) {
			if (isSelfSigned(crt)) {
				trustedRootCerts.add(new TrustAnchor(crt, null));
			} else {
				if (!isCACertificate(crt)) {
					throw new CertificateCAVerificationException("the certificate is not a CA.");
				} else {
					intermediateCerts.add(crt);
				}
			}
		}

		PKIXBuilderParameters params = new PKIXBuilderParameters(trustedRootCerts, selector);
		params.setRevocationEnabled(false); // to avoid exception on empty CRL (for now)

		CertStore intermediateCertStore;
		intermediateCertStore = CertStore.getInstance("Collection",
				new CollectionCertStoreParameters(intermediateCerts), "BC");
		params.addCertStore(intermediateCertStore);

		CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", "BC");
		result = (PKIXCertPathBuilderResult) builder.build(params);
		return result;
	}

	public static boolean isSelfSigned(X509Certificate certificate)
			throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException {
		boolean isSelfSigned = false;
		PublicKey publicKey = certificate.getPublicKey();
		try {
			certificate.verify(publicKey);
			isSelfSigned = true;
		} catch (SignatureException sigEx) {
			// invalid signature
		} catch (InvalidKeyException keyEx) {
			// certificate was not signed with given public key
		}
		return isSelfSigned;
	}

	public static boolean isCACertificate(X509Certificate certificate) {
		int basicConstraints = certificate.getBasicConstraints();
		boolean[] keyUsage = certificate.getKeyUsage();

		return basicConstraints != -1 && keyUsage != null && keyUsage[5] == true;
	}

	public static void printAliases(KeyStore ks) {
		try {
			List<String> aliases = Collections.list(ks.aliases());
			aliases.stream().forEach(KeyToolSmith::printAlias);
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
	}

	private static void printAlias(String alias) {
		System.out.println("alias: " + alias);
	}

	public static SecretKey generateSecretKey() {
		SecretKey secretKey = null;
		try {
			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
			SecureRandom secureRandom = new SecureRandom();
			int keyBitSize = 256;
			keyGenerator.init(keyBitSize, secureRandom);
			secretKey = keyGenerator.generateKey();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return secretKey;
	}

	public static KeyPair generateKeyPair() {
		KeyPair keyPair = null;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return keyPair;
	}

	private static X509Certificate getCertificateFromFile(CertificateFactory certificateFactory, String filename)
			throws CertificateException, IOException, FileNotFoundException {
		X509Certificate certificate = null;
		try (FileInputStream in = new FileInputStream(STORE_FOLDER.concat(filename))) {
			certificate = (X509Certificate) certificateFactory.generateCertificate(in);
		}
		return certificate;
	}
	

	public static void main(String[] args) throws FileNotFoundException, IOException, KeyStoreException,
			InvalidAlgorithmParameterException, NoSuchAlgorithmException, CertPathValidatorException,
			NoSuchProviderException, CertPathBuilderException, CertificateCAVerificationException {

		Security.addProvider(new BouncyCastleProvider());

		// testar a cadeia de certificados (temp)
		try {
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			List<X509Certificate> certs = new ArrayList<>(); // ArrayList maintains the order of the object in which
																// they are inserted

			X509Certificate rootCACert = getCertificateFromFile(certificateFactory, "rootca.cer");
			X509Certificate madisonCAPairCert = getCertificateFromFile(certificateFactory, "madison_capair_.cer");
			X509Certificate billMadisonCert = getCertificateFromFile(certificateFactory, "bill_madison_.cer");
//			certs.add(billMadisonCert);
			certs.add(madisonCAPairCert);
			certs.add(rootCACert);

			KeyStore ks = loadKeyStore("eduardo", "TestKeyStore");
//			verifyChainCertificates1(ks, null, null, certs);
			verifyChainCertificates2(ks, null, billMadisonCert, certs);
		} catch (CertificateException e) {
			e.printStackTrace();
		}
	}
}

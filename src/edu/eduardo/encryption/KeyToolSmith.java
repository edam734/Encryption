package edu.eduardo.encryption;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Iterator;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * @author Eduardo Amorim
 *
 */
public class KeyToolSmith {

	private static final String STORE_FOLDER = "_stores/";

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
			ks = KeyStore.getInstance(KEYSTORE_TYPE);
			ks.load(null, password.toCharArray());
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
				ks.store(fos, storePwd.toCharArray()); // storePwd could be null
			}
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			e.printStackTrace();
			return false;
		}
		return true;
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

	public static void printAllAliases(KeyStore ks) {
		try {
			Iterator<String> it = ks.aliases().asIterator();
			while (it.hasNext()) {
				System.out.println("alias: " + it.next());
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
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
}

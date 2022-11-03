package edu.eduardo.encryption;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import edu.eduardo.utils.FileUtils;

/**
 * @author Eduardo Amorim
 *
 */
public class KeyStoreManager {

	public static final String KEYSTORE_TYPE = "pkcs12";

	private KeyStoreManager() {
	}

	public static KeyStore createKeyStore(String password, String keyStoreName) {
		KeyStore ks = null;
		try {
			ks = KeyStore.getInstance(KEYSTORE_TYPE);
			char[] pwdArray = password.toCharArray();
			ks.load(null, pwdArray);
			try (FileOutputStream fos = new FileOutputStream(FileUtils.getStoreFolder().concat(keyStoreName))) {
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
			try (FileInputStream in = new FileInputStream(FileUtils.getStoreFolder().concat(keyStoreName))) {
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
			try (FileOutputStream fos = new FileOutputStream(FileUtils.getStoreFolder().concat(keyStoreName))) {
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

	public static void printAliases(KeyStore ks) {
		try {
			List<String> aliases = Collections.list(ks.aliases());
			aliases.stream().forEach(KeyStoreManager::printAlias);
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

}

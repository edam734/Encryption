package edu.eduardo.encryption;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.Base64;
import java.util.Enumeration;
import java.util.Iterator;

import javax.crypto.SecretKey;

public class KeyToolMain {

	public static void main(String[] args) {
//		KeyStore keyStore = KeyToolSmith.createKeyStore("changeit", "edkeystore.p12");
		KeyStore keyStore = KeyStoreManager.loadKeyStore("changeit", "edkeystore.p12");
//		storeKeyOnKeystore(keyStore); // M5P8W+8T+d8p9HeiggtBQ8h+Qt2DEZsIgXVnaUHhhQI=
		KeyStoreManager.printAliases(keyStore);
		readKeyFromKeystore(keyStore);

	}

	private static void storeKeyOnKeystore(KeyStore keyStore) {
		SecretKey sKey = KeyStoreManager.generateSecretKey();
		System.out.println(Base64.getEncoder().encodeToString(sKey.getEncoded()));
		boolean successful = KeyStoreManager.storeSecretKey(keyStore, "changeit", "edkeystore.p12", "789xyz",
				"secret-Key-alias", sKey);
		System.out.println(successful);
	}

	private static void readKeyFromKeystore(KeyStore keyStore) {
		SecretKey sKey = KeyStoreManager.getSecretKey(keyStore, "789xyz", "secret-Key-alias");
		System.out.println(Base64.getEncoder().encodeToString(sKey.getEncoded()));
	}
}

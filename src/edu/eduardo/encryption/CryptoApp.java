package edu.eduardo.encryption;

import java.util.Base64;

public class CryptoApp {

	public static void main(String[] args) {
		Crypto crypto = new SymetricKeyCrypto();

		String data = "Hello World!";
		System.out.println("Original Text: " + data);

		// ecrypt
		String enc = Base64.getEncoder().encodeToString(crypto.encrypt(data.getBytes()));
		System.out.println("Encrypted: " + enc);
		// decrypt
		String dec = new String(crypto.decrypt(Base64.getDecoder().decode(enc)));
		System.out.println("Decrypted: " + dec);
	}

}

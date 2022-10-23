package edu.eduardo.encryption;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class MacApp {

	public static void main(String[] args) {
		// secret key to be shared
		SecretKey secretKey = generateSecretKey();
		
		// Daisy writes a message to me
		DaisyWrites daisy = new DaisyWrites(secretKey);
		MessageWithMac message = daisy.writeMessage();

		// reading message and verifying Mac
		MacManager macManager = new MacManager(secretKey);
		System.out.println("Message: " + message.getMessage());
		byte[] macMessage = message.getMac();
		byte[] macResult = macManager.calculateMac(message.getMessage().getBytes(StandardCharsets.UTF_8));
		System.out.println("Mac verifies? " + Arrays.equals(macMessage, macResult));
	}

	private static SecretKey generateSecretKey() {
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

}

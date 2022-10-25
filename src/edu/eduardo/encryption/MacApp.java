package edu.eduardo.encryption;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import javax.crypto.SecretKey;

public class MacApp {

	public static void main(String[] args) {
		// secret key to be shared
		SecretKey secretKey = KeyToolSmith.generateSecretKey();
		
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

}

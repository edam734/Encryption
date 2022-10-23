package edu.eduardo.encryption;

import java.nio.charset.StandardCharsets;

import javax.crypto.SecretKey;

public class DaisyWrites {

	private MacManager macManager;

	public DaisyWrites(SecretKey secretKey) {
		this.macManager = new MacManager(secretKey);
	}

	public MessageWithMac writeMessage() {
		String message = "Good Morning, Ed";
		byte[] mac = this.macManager.calculateMac(message.getBytes(StandardCharsets.UTF_8));
		return new MessageWithMac(message, mac);
	}

}

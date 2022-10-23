package edu.eduardo.encryption;

public class MessageWithMac {
	private String message;
	private byte[] mac;

	public MessageWithMac(String message, byte[] mac) {
		super();
		this.message = message;
		this.mac = mac;
	}

	public String getMessage() {
		return message;
	}

	public byte[] getMac() {
		return mac;
	}

}
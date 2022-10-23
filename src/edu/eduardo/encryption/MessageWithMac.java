package edu.eduardo.encryption;

public class MessageWithMac {
	String message;
	byte[] mac;

	public MessageWithMac(String message, byte[] mac) {
		super();
		this.message = message;
		this.mac = mac;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	public byte[] getMac() {
		return mac;
	}

	public void setMac(byte[] mac) {
		this.mac = mac;
	}

}
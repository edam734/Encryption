package edu.eduardo.encryption;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

public class MacManager {

	private Mac mac;

	public MacManager(SecretKey secretKey) {
		super();
		try {
			this.mac = Mac.getInstance("HmacSHA256");
			this.mac.init(secretKey);
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			e.printStackTrace();
		}
	}

	public byte[] calculateMac(byte[] data) {
		return mac.doFinal(data);
	}

}

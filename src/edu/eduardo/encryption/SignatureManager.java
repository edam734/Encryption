package edu.eduardo.encryption;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

public class SignatureManager {

	private KeyPair keyPair;

	public SignatureManager() {
		super();
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

	public byte[] usePublicKey(byte[] data) {

		return null;
	}

	public byte[] sign(byte[] data) {
		byte[] digitalSignature = null;
		try {
			SecureRandom secureRandom = new SecureRandom();
			Signature signature = Signature.getInstance("SHA256WithRSA");
			signature.initSign(this.keyPair.getPrivate(), secureRandom);
			signature.update(data);
			digitalSignature = signature.sign();
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			e.printStackTrace();
		}
		return digitalSignature;
	}

	public boolean verifySignature(byte[] data, byte[] digitalSignature) {
		boolean verified = false;
		try {
			Signature signature = Signature.getInstance("SHA256WithRSA");
			signature.initVerify(this.keyPair.getPublic());
			signature.update(data);
			verified = signature.verify(digitalSignature);
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			e.printStackTrace();
		}
		return verified;
	}
}

package edu.eduardo.encryption;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

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

	public byte[] encryptUsingPublicKey(byte[] data) {
		return operation(data, Cipher.ENCRYPT_MODE, this.keyPair.getPublic());
	}

	public byte[] encryptUsingPrivateKey(byte[] data) {
		return operation(data, Cipher.ENCRYPT_MODE, this.keyPair.getPrivate());
	}

	public byte[] dencryptUsingPublicKey(byte[] data) {
		return operation(data, Cipher.DECRYPT_MODE, this.keyPair.getPublic());
	}

	public byte[] dencryptUsingPrivateKey(byte[] data) {
		return operation(data, Cipher.DECRYPT_MODE, this.keyPair.getPrivate());
	}

	private byte[] operation(byte[] data, int mode, Key key) {
		byte[] dataResult = null;
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(mode, key);
			dataResult = cipher.doFinal(data);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException e) {
			e.printStackTrace();
		}
		return dataResult;
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

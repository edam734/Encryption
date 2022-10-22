package edu.eduardo.encryption;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class SymetricKeyCrypto implements Crypto {

	private static final String SECRET_KEY = "thisismypassword123";
	private static final String SALT = "s@lty#ddfk";

	private SecretKeySpec secretKey;
	private IvParameterSpec ivspec;

	private Cipher cipher;
	private boolean padding;

	public SymetricKeyCrypto() {
		this(true);
	}

	public SymetricKeyCrypto(boolean padding) {
		super();
		this.padding = padding;
		try {
			this.secretKey = generateSecretKey();
			if (padding) {
				this.cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
				this.ivspec = generateInitializationVectorParamSpec(this.cipher.getBlockSize());
			} else {
				this.cipher = Cipher.getInstance("AES");
			}
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		}
	}

	private IvParameterSpec generateInitializationVectorParamSpec(int blockSize) {
		byte[] iv = new byte[blockSize];
		new SecureRandom().nextBytes(iv);
		return new IvParameterSpec(iv);
	}

	private SecretKeySpec generateSecretKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), 65536, 256);
		SecretKey tmp = factory.generateSecret(spec);
		return new SecretKeySpec(tmp.getEncoded(), "AES");
	}

	@Override
	public byte[] encrypt(byte[] data) {
		try {
			initCipher(Cipher.ENCRYPT_MODE);
			return this.cipher.doFinal(data);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public byte[] decrypt(byte[] data) {
		try {
			initCipher(Cipher.DECRYPT_MODE);
			return this.cipher.doFinal(data);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	private void initCipher(int opmode)
			throws InvalidKeyException, InvalidAlgorithmParameterException {
		if (this.padding) {
			this.cipher.init(opmode, this.secretKey, this.ivspec);
		} else {
			this.cipher.init(opmode, this.secretKey);
		}
	}
}

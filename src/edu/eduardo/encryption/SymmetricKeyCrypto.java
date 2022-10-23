package edu.eduardo.encryption;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class SymmetricKeyCrypto implements Crypto {

	private Key secretKey;
	private IvParameterSpec ivspec;

	private Cipher cipher;
	private boolean padding;

	public SymmetricKeyCrypto() {
		this(true);
	}

	public SymmetricKeyCrypto(boolean padding) {
		this(padding, TypeKey.RANDOM);
	}

	public SymmetricKeyCrypto(TypeKey typeKey) {
		this(true, typeKey);
	}

	public SymmetricKeyCrypto(boolean padding, TypeKey typeKey) {
		super();
		this.padding = padding;
		try {
			this.secretKey = SymmetricKeyGenerator.getKey(typeKey);
			if (padding) {
				this.cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
				this.ivspec = generateInitializationVectorParamSpec(this.cipher.getBlockSize());
			} else {
				this.cipher = Cipher.getInstance("AES");
			}
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

	private void initCipher(int opmode) throws InvalidKeyException, InvalidAlgorithmParameterException {
		if (this.padding) {
			this.cipher.init(opmode, this.secretKey, this.ivspec);
		} else {
			this.cipher.init(opmode, this.secretKey);
		}
	}

	private static class SymmetricKeyGenerator {

		public static Key getKey(TypeKey type) {
			Key key = null;
			try {
				switch (type) {
				case RANDOM:
					key = generateRandomSecretKey();
					break;
				case SECRET:
					key = generateSecretKey();
					break;
				default:
					throw new RuntimeException();
				}
			} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
				e.printStackTrace();
			}
			return key;
		}

		private static SecretKeySpec generateSecretKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
			String secret = "thisismypassword123";
			String salt = "s@lty#ddfk";
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			KeySpec spec = new PBEKeySpec(secret.toCharArray(), salt.getBytes(), 65536, 256);
			SecretKey tmp = factory.generateSecret(spec);
			return new SecretKeySpec(tmp.getEncoded(), "AES");
		}

		private static SecretKey generateRandomSecretKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
			SecureRandom secureRandom = new SecureRandom();
			keyGenerator.init(256, secureRandom);
			return keyGenerator.generateKey();
		}
	}
}

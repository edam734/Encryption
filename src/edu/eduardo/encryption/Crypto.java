package edu.eduardo.encryption;

public interface Crypto {

	byte[] encrypt(byte[] data);

	byte[] decrypt(byte[] data);

}

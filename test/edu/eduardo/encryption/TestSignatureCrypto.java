package edu.eduardo.encryption;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.nio.charset.StandardCharsets;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class TestSignatureCrypto {

	@BeforeAll
	static void setup() {
		// set BouncyCastleProvider instead of using Java SDK default provider
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	void testSignature() {
		SignatureManager signatureManager = new SignatureManager();
		byte[] data = "abcdefghijklmnopqrstuvxyz".getBytes(StandardCharsets.UTF_8);
		byte[] digitalSignature = signatureManager.sign(data);
		assertNotNull(digitalSignature);
	}

	@Test
	void testVerifySignature() {
		SignatureManager signatureManager = new SignatureManager();
		byte[] data = "abcdefghijklmnopqrstuvxyz".getBytes(StandardCharsets.UTF_8);
		byte[] digitalSignature = signatureManager.sign(data);
		boolean verified = signatureManager.verifySignature(data, digitalSignature);
		assertTrue(verified);
	}

	@Test
	void testPublicEncPrivateDec() {
		String plainText = "abcdefghijklmnopqrstuvxyz";

		SignatureManager signatureManager = new SignatureManager();
		byte[] data = plainText.getBytes(StandardCharsets.UTF_8);
		byte[] enc = signatureManager.encryptUsingPublicKey(data);
		byte[] dec = signatureManager.dencryptUsingPrivateKey(enc);
		assertNotNull(enc);
		assertNotNull(dec);
		assertNotEquals(plainText, new String(enc));
		assertEquals(plainText, new String(dec));
	}

	@Test
	void testPrivateEncPublicDec() {
		String plainText = "abcdefghijklmnopqrstuvxyz";

		SignatureManager signatureManager = new SignatureManager();
		byte[] data = plainText.getBytes(StandardCharsets.UTF_8);
		byte[] enc = signatureManager.encryptUsingPrivateKey(data);
		byte[] dec = signatureManager.dencryptUsingPublicKey(enc);
		assertNotNull(enc);
		assertNotNull(dec);
		assertNotEquals(plainText, new String(enc));
		assertEquals(plainText, new String(dec));
	}

	@Test
	void testPrivateEncPrivateDec() {
		String plainText = "abcdefghijklmnopqrstuvxyz";

		SignatureManager signatureManager = new SignatureManager();
		byte[] data = plainText.getBytes(StandardCharsets.UTF_8);
		byte[] enc = signatureManager.encryptUsingPrivateKey(data);
		byte[] dec = signatureManager.dencryptUsingPrivateKey(enc);
		assertNotNull(enc);
		assertNull(dec);
	}
}

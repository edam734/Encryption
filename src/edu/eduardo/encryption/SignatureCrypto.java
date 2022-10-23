package edu.eduardo.encryption;

import java.nio.charset.StandardCharsets;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SignatureCrypto {

	public static void main(String[] args) {
		// set BouncyCastleProvider instead of using Java SDK default provider
		Security.addProvider(new BouncyCastleProvider());

		SignatureManager signatureManager = new SignatureManager();
		byte[] data = "abcdefghijklmnopqrstuvxyz".getBytes(StandardCharsets.UTF_8);
		byte[] digitalSignature = signatureManager.sign(data);
		System.out.println("Digital Signature: " + new String(digitalSignature));
		boolean verified = signatureManager.verifySignature(data, digitalSignature);
		System.out.println("Verified? " + verified);
	}

}

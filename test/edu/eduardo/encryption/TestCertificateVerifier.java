package edu.eduardo.encryption;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;

import edu.eduardo.encryption.exceptions.CertificateVerificationException;
import edu.eduardo.encryption.exceptions.RevocationVerificationException;
import edu.eduardo.utils.FileUtils;

public class TestCertificateVerifier {

	@BeforeAll
	static void setup() {
		// set BouncyCastleProvider instead of using Java SDK default provider
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	void obtainCertificateChain_withoutImportedCRLs_success() throws CertificateException, IOException, NoSuchAlgorithmException,
			NoSuchProviderException, InvalidAlgorithmParameterException, CertPathBuilderException,
			CertificateVerificationException, RevocationVerificationException {
		Collection<X509Certificate> certificateChain = (Collection<X509Certificate>) FileUtils
				.getCertificateChainFromFile("test-ev-rsa.ssl.crt");
		X509Certificate certificate = null;
		if (certificateChain != null && certificateChain.size() > 0) {
			certificate = certificateChain.iterator().next();
		}
		certificateChain.remove(certificate);

		CertificateVerifier.verifyChainCertificates(null, certificate, certificateChain);
	}
}

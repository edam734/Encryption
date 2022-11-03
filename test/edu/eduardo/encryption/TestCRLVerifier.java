package edu.eduardo.encryption;

import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.List;

import org.junit.jupiter.api.Test;

import edu.eduardo.encryption.exceptions.CertificateVerificationException;
import edu.eduardo.encryption.exceptions.DownloadCRLsException;
import edu.eduardo.encryption.exceptions.RevocationVerificationException;
import edu.eduardo.utils.FileUtils;

/**
 * 
 * for certificate samples:
 * https://www.ssl.com/sample-valid-revoked-and-expired-ssl-tls-certificates/
 * 
 * @author Eduardo Amorim
 * 
 */
public class TestCRLVerifier {

	@Test
	void verifyCertificateCRLs_success() throws CertificateException, FileNotFoundException, IOException,
			CertificateVerificationException, RevocationVerificationException {
		X509Certificate cert = FileUtils.getCertificateFromFile("XRampGlobalCARoot.crt");
		CRLVerifier.verifyCertificateCRLs(cert);

		// no exception should be thrown
	}

	/*
	 * Should throw exception:
	 * edu.eduardo.encryption.exceptions.RevocationVerificationException: The
	 * certificate is revoked by CRL:
	 * http://crls.ssl.com/SSLcom-SubCA-SSL-RSA-4096-R1.crl
	 */
	@Test
	void verifyCertificateCRLs_failByRevokation() throws CertificateException, FileNotFoundException, IOException {
		X509Certificate cert = FileUtils.getCertificateFromFile("revoked-rsa-dv.ssl.com");

		assertThrows(RevocationVerificationException.class, () -> CRLVerifier.verifyCertificateCRLs(cert));
	}

	@Test
	void obtainAllCRLs_whenGivenCertificate_returnList()
			throws CertificateException, FileNotFoundException, IOException, DownloadCRLsException {
		X509Certificate cert = FileUtils.getCertificateFromFile("XRampGlobalCARoot.crt");
		List<X509CRL> crLs = CRLVerifier.getCRLs(cert);

		assertTrue(1 == crLs.size());
	}

	// TODO verify generateCRLsFromChain

}

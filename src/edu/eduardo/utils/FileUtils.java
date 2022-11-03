package edu.eduardo.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.stream.Collectors;

public class FileUtils {

	private static final String STORE_FOLDER = "lib/security/".replace("/", File.separator);

	private static final String CERTS = STORE_FOLDER.concat("/certs/").replace("/", File.separator);

	public static X509Certificate getCertificateFromFile(String filename) throws CertificateException, IOException {
		X509Certificate certificate = null;
		try (FileInputStream in = new FileInputStream(CERTS.concat(filename))) {
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			certificate = (X509Certificate) certificateFactory.generateCertificate(in);
		}
		return certificate;
	}

	public static Collection<X509Certificate> getCertificateChainFromFile(String filename)
			throws CertificateException, IOException {
		Collection<X509Certificate> certChain = null;
		try (FileInputStream in = new FileInputStream(CERTS.concat(filename))) {
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			Collection<? extends Certificate> generatedCertificates = certificateFactory.generateCertificates(in);
			certChain = generatedCertificates.stream().map(c -> (X509Certificate) c).collect(Collectors.toList());
		}
		return certChain;
	}

	public static Collection<X509CRL> getCRLsfromFile(String filename) throws IOException, CertificateException, CRLException {
		Collection<X509CRL> crLs = null;
		try (FileInputStream in = new FileInputStream(CERTS.concat(filename))) {
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			Collection<? extends CRL> generatedCRLs = certificateFactory.generateCRLs(in);
			crLs = generatedCRLs.stream().map(e -> (X509CRL) e).collect(Collectors.toList());
		}
		return crLs;
	}

	public static String getStoreFolder() {
		return STORE_FOLDER;
	}

}

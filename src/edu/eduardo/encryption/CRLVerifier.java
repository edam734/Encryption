package edu.eduardo.encryption;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Hashtable;
import java.util.List;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

import edu.eduardo.encryption.exceptions.CertificateVerificationException;
import edu.eduardo.encryption.exceptions.DownloadCRLsException;
import edu.eduardo.encryption.exceptions.RevocationVerificationException;
import edu.eduardo.utils.FileUtils;

public class CRLVerifier {

	public static void verifyCertificateCRLs(X509Certificate cert)
			throws CertificateVerificationException, RevocationVerificationException {
		try {
			List<String> crlDistributionPoints = getCrlDistributionPoints(cert);
			for (String crlDP : crlDistributionPoints) {
				X509CRL crl = downloadCRL(crlDP);
				if (crl.isRevoked(cert)) {
					throw new RevocationVerificationException("The certificate is revoked by CRL: ".concat(crlDP));
				}
			}
		} catch (Exception e) {
			if (e instanceof RevocationVerificationException) {
				throw (RevocationVerificationException) e;
			} else if (e instanceof CertificateVerificationException) {
				throw (CertificateVerificationException) e;
			} else {
				throw new CertificateVerificationException(
						"Can not verify CRL for certificate: ".concat(cert.getSubjectX500Principal().toString()));
			}
		}
	}

	public static List<X509CRL> getCRLs(X509Certificate cert) throws DownloadCRLsException {
		List<X509CRL> crls = new ArrayList<>();
		try {
			List<String> crlDistributionPoints = getCrlDistributionPoints(cert);

			for (String distributionPoint : crlDistributionPoints) {
				try {
					X509CRL crl = downloadCRL(distributionPoint);
					crls.add(crl);
				} catch (Exception e) {
					throw new DownloadCRLsException("Can not download the CRL for certificate: "
							.concat(cert.getSubjectX500Principal().toString()));
				}

			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		return crls;
	}

	private static X509CRL downloadCRL(String crlURL)
			throws CertificateVerificationException, CertificateException, CRLException, IOException, NamingException {
		if (crlURL.startsWith("http://") || crlURL.startsWith("https://") || crlURL.startsWith("ftp://")) {
			return downloadCRLFromWeb(crlURL);
		} else if (crlURL.startsWith("ldap://")) {
			return downloadCRLFromLDAP(crlURL);
		} else {
			throw new CertificateVerificationException(
					"Can not download CRL from certificate distribution point: ".concat(crlURL));
		}
	}

	private static X509CRL downloadCRLFromWeb(String crlURL) throws IOException, CertificateException, CRLException {
		URL url = new URL(crlURL);
		X509CRL x509CRL = null;
		try (InputStream crlStream = url.openStream()) {
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			x509CRL = (X509CRL) certificateFactory.generateCRL(crlStream);
		}
		return x509CRL;
	}

	private static X509CRL downloadCRLFromLDAP(String ldapURL)
			throws NamingException, CertificateVerificationException, CertificateException, CRLException {
		X509CRL x509CRL = null;

		// Set up environment for creating initial context
		Hashtable<String, String> env = new Hashtable<>();
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, ldapURL);

		// Specify timeout to be 5 seconds
		env.put("com.sun.jndi.ldap.connect.timeout", "5000");

		// Create initial context
		DirContext ctx = new InitialDirContext(env);

		// Retrieves all of the attributes
		Attributes avals = ctx.getAttributes("");
		Attribute aval = avals.get("certificateRevocationList;binary");
		byte[] val = (byte[]) aval.get();
		if (val == null || val.length == 0) {
			throw new CertificateVerificationException("Can not download CRL from: " + ldapURL);
		} else {
			InputStream inStream = new ByteArrayInputStream(val);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			x509CRL = (X509CRL) cf.generateCRL(inStream);
		}
		return x509CRL;
	}

	private static List<String> getCrlDistributionPoints(X509Certificate cert) throws IOException {
		ASN1Primitive extensionValue = getExtensionValue(cert, Extension.cRLDistributionPoints.getId());
		if (extensionValue == null) {
			return Collections.emptyList(); // certificate doesn't have any CRLs
		}
		List<String> crlUrls = new ArrayList<String>();

		CRLDistPoint distPoint = CRLDistPoint.getInstance(extensionValue);
		for (DistributionPoint dp : distPoint.getDistributionPoints()) {
			DistributionPointName dpn = dp.getDistributionPoint();
			// Look for URIs in fullName
			if (dpn != null) {
				if (dpn.getType() == DistributionPointName.FULL_NAME) {
					GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();
					// Look for an URI
					for (GeneralName genName : genNames) {
						if (genName.getTagNo() == GeneralName.uniformResourceIdentifier) {
							DERIA5String ia5String = new DERIA5String(genName.getName().toString());
							String url = ia5String.toString();
							crlUrls.add(url);
						}
					}
				}
			}
		}
		return crlUrls;
	}

	private static ASN1Primitive getExtensionValue(X509Certificate cert, String oid) throws IOException {
		byte[] extensionValue = cert.getExtensionValue(oid);
		if (extensionValue == null) {
			return null;
		}
		ASN1Primitive derObjCrlDP = null;
		try (ASN1InputStream asn1InputStream = new ASN1InputStream(extensionValue)) {
			derObjCrlDP = asn1InputStream.readObject();
		}
		DEROctetString dosCrlDP = (DEROctetString) derObjCrlDP;
		byte[] crldpExtValOctets = dosCrlDP.getOctets();
		try (ASN1InputStream asn1InputStream = new ASN1InputStream(crldpExtValOctets)) {
			derObjCrlDP = asn1InputStream.readObject();
		}
		return derObjCrlDP;
	}

	public static Collection<X509CRL> generateCRLsFromFile(String crlsFilename) {
		try {
			return FileUtils.getCRLsfromFile(crlsFilename);
		} catch (CertificateException | CRLException | IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	public static Collection<X509CRL> generateCRLsFromChain(Collection<X509Certificate> certs) {
		List<X509CRL> totalCRLs = new ArrayList<>();
		for (X509Certificate x509Certificate : certs) {
			List<X509CRL> crLs;
			try {
				crLs = getCRLs(x509Certificate);
			} catch (DownloadCRLsException e) {
				e.printStackTrace();
				return null; // unsuccessful
			}
			totalCRLs.addAll(crLs);
		}
		return totalCRLs;
	}

}

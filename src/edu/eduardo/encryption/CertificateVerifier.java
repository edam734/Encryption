package edu.eduardo.encryption;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import edu.eduardo.encryption.exceptions.CertificateVerificationException;
import edu.eduardo.encryption.exceptions.RevocationVerificationException;

public class CertificateVerifier {

	public static PKIXCertPathBuilderResult verifyChainCertificates(Collection<? extends CRL> crLs,
			X509Certificate cert, Collection<X509Certificate> certs) throws CertificateException,
			NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException,
			CertPathBuilderException, CertificateVerificationException, RevocationVerificationException {
		PKIXCertPathBuilderResult verifiedCertChain = null;
		X509CertSelector selector = new X509CertSelector();
		selector.setCertificate(cert);

		Set<TrustAnchor> trustedRootCerts = new HashSet<>();
		Set<X509Certificate> intermediateCerts = new HashSet<>();
		for (X509Certificate crt : certs) {
			if (isSelfSigned(crt)) {
				trustedRootCerts.add(new TrustAnchor(crt, null));
			} else {
				if (!isCACertificate(crt)) {
					// failed already
					throw new CertificateVerificationException("the certificate is not a CA.");
				} else {
					intermediateCerts.add(crt);
				}
			}
		}

		PKIXBuilderParameters pkixBuilderParameters = new PKIXBuilderParameters(trustedRootCerts, selector);
		// Root CAs certificates don't list a Certificate Revocation List distribution
		// point and root CAs are are not revocable. The revocation is not being
		// verified for Root certificates.
		pkixBuilderParameters.setRevocationEnabled(false);

		// Check whether the certificate is revoked by the CRL
		CRLVerifier.verifyCertificateCRLs(cert); // for the target certificate

		// check CRLs for intermediate certificates also
		for (X509Certificate intermediateCertificate : intermediateCerts) {
			CRLVerifier.verifyCertificateCRLs(intermediateCertificate);
		}

		CertStore intermediateCertStore;
		intermediateCertStore = CertStore.getInstance("Collection",
				new CollectionCertStoreParameters(intermediateCerts), "BC");
		pkixBuilderParameters.addCertStore(intermediateCertStore);

		CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", "BC");
		verifiedCertChain = (PKIXCertPathBuilderResult) builder.build(pkixBuilderParameters);

		return verifiedCertChain;
	}

	public static boolean isSelfSigned(X509Certificate certificate)
			throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException {
		boolean isSelfSigned = false;
		PublicKey publicKey = certificate.getPublicKey();
		try {
			certificate.verify(publicKey);
			isSelfSigned = true;
		} catch (SignatureException sigEx) {
			// invalid signature
		} catch (InvalidKeyException keyEx) {
			// certificate was not signed with given public key
		}
		return isSelfSigned;
	}

	public static boolean isCACertificate(X509Certificate certificate) {
		int basicConstraints = certificate.getBasicConstraints();
		boolean[] keyUsage = certificate.getKeyUsage();

		return basicConstraints != -1 && keyUsage != null && keyUsage[5] == true;
	}
}

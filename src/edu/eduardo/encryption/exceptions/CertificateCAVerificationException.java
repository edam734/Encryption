package edu.eduardo.encryption.exceptions;

public class CertificateCAVerificationException extends Exception {

	private static final long serialVersionUID = -2483800347428631214L;

	public CertificateCAVerificationException(String message, Throwable cause) {
		super(message, cause);
	}

	public CertificateCAVerificationException(String message) {
		super(message);
	}
}

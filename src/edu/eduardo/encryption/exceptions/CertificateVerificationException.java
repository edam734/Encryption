package edu.eduardo.encryption.exceptions;

public class CertificateVerificationException extends Exception {

	private static final long serialVersionUID = -2483800347428631214L;

	public CertificateVerificationException(String message, Throwable cause) {
		super(message, cause);
	}

	public CertificateVerificationException(String message) {
		super(message);
	}
}

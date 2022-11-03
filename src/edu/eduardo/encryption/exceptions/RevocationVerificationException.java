package edu.eduardo.encryption.exceptions;

/**
 * RevocationVerificationException is thrown if the certificate was found to be
 * on a revocation list.
 */
public class RevocationVerificationException extends Exception {
	private static final long serialVersionUID = 3486626462438794516L;

	public RevocationVerificationException(String message, Throwable cause) {
		super(message, cause);
	}

	public RevocationVerificationException(String message) {
		super(message);
	}
}

package edu.eduardo.encryption.exceptions;

public class DownloadCRLsException extends Exception {
	private static final long serialVersionUID = 607758666017628104L;

	public DownloadCRLsException(String message, Throwable cause) {
		super(message, cause);
	}

	public DownloadCRLsException(String message) {
		super(message);
	}
}

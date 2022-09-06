package io.github.aaronanderson.quarkus.mfa.runtime;

import java.util.Map;

import io.quarkus.security.credential.PasswordCredential;

public interface MfaIdentityStore {

	public AuthenticationResult authenticate(String username, PasswordCredential password, Map<String, Object> attributes);

	public PasswordResetResult passwordReset(PasswordCredential currentPassword, PasswordCredential newPassword);
	
	public VerificationResult verify(String username, TOTPCallback callback, Map<String, Object> attributes);

	public void storeTotpKey(String username, PasswordCredential toptKey);
		
	@FunctionalInterface
	public interface TOTPCallback{
		boolean verify(PasswordCredential toptKey);
	}
	
	public static enum PasswordResetResult {
		SUCCESS, FAILED_CURRENT, FAILED_POLICY;
	}

	public static enum AuthenticationResult {
		SUCCESS, SUCCESS_RESET_PASSWORD, FAILED, ACCOUNT_LOCKED;
	}
	
	public static enum VerificationResult {
		SUCCESS, FAILED, TOTP_REGISTRATION;
	}
}

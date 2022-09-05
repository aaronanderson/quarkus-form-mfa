package io.github.aaronanderson.quarkus.mfa.runtime;

import java.time.OffsetDateTime;
import java.util.Map;

import io.quarkus.security.credential.PasswordCredential;

public interface MfaIdentityStore {

	public AuthenticationResult authenticate(String username, PasswordCredential password);

	public AuthenticationResult lockAccount(String username, OffsetDateTime unlockTime);

	public PasswordResetResult passwordReset(PasswordCredential currentPassword, PasswordCredential newPassword);

	public PasswordCredential loadTotpKey(String username);

	public void storeTotpKey(String username, PasswordCredential toptKey);

	public void loadProfile(String username, Map<String, String> attributes);

	public static enum PasswordResetResult {
		SUCCESS, FAILED_CURRENT, FAILED_POLICY;
	}

	public static enum AuthenticationResult {
		SUCCESS, SUCCESS_RESET_PASSWORD, FAILED, ACCOUNT_LOCKED;
	}
}

package io.github.aaronanderson.quarkus.mfa.it;

import java.util.List;
import java.util.Map;

import javax.enterprise.context.ApplicationScoped;

import io.github.aaronanderson.quarkus.mfa.runtime.MfaIdentityStore;
import io.quarkus.security.credential.PasswordCredential;

@ApplicationScoped
public class TestMfaIdentityStore implements MfaIdentityStore {

	@Override
	public AuthenticationResult authenticate(String username, PasswordCredential password, Map<String, Object> attributes) {
		if ("jdoe1".equals(username)) {
			attributes.put("sub", "jdoe1@acme.com");
			attributes.put("groups", List.of("admin"));
			return AuthenticationResult.SUCCESS;
		}
		return AuthenticationResult.FAILED;

	}

	@Override
	public PasswordResetResult passwordReset(PasswordCredential currentPassword, PasswordCredential newPassword) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public VerificationResult verify(String username, TOTPCallback callback, Map<String, Object> attributes) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void storeTotpKey(String username, PasswordCredential toptKey) {
		// TODO Auto-generated method stub

	}

}

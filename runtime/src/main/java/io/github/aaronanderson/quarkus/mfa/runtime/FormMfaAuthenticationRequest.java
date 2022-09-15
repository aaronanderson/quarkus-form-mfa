package io.github.aaronanderson.quarkus.mfa.runtime;

import org.jose4j.jwt.JwtClaims;

import io.quarkus.security.identity.request.BaseAuthenticationRequest;

public class FormMfaAuthenticationRequest extends BaseAuthenticationRequest {
	private JwtClaims claims;

	public FormMfaAuthenticationRequest(JwtClaims claims) {
		this.claims = claims;
	}

	public JwtClaims getClaims() {
		return claims;
	}
}

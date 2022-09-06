package io.github.aaronanderson.quarkus.mfa.runtime;

import java.util.function.Consumer;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.jose4j.jwt.MalformedClaimException;

import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.smallrye.mutiny.Uni;
import io.smallrye.mutiny.subscription.UniEmitter;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.ext.auth.User;

/**
 * MFA IdentityProvider
 */
@ApplicationScoped
public class MfaIdentityProvider implements IdentityProvider<MfaAuthenticationRequest> {

	@Override
	public Class<MfaAuthenticationRequest> getRequestType() {
		return MfaAuthenticationRequest.class;
	}

	@Override
	public Uni<SecurityIdentity> authenticate(MfaAuthenticationRequest request, AuthenticationRequestContext context) {
		return Uni.createFrom().item(() -> {

			try {
				QuarkusSecurityIdentity.Builder builder = QuarkusSecurityIdentity.builder();
				builder.setPrincipal(new QuarkusPrincipal(request.getClaims().getSubject()));				
				request.getClaims().getClaimNames().forEach(name-> builder.addAttribute(name, request.getClaims().getClaimValue(name)));						
				return builder.build();
			} catch (MalformedClaimException e) {
				return null;
			}

		});

	}

}

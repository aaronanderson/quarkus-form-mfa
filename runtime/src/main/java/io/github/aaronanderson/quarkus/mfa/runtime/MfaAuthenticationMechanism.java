package io.github.aaronanderson.quarkus.mfa.runtime;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;

import org.jboss.logging.Logger;
import org.jose4j.jwt.JwtClaims;

import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.AnonymousAuthenticationRequest;
import io.quarkus.security.identity.request.AuthenticationRequest;
import io.quarkus.vertx.http.runtime.security.ChallengeData;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticator;
import io.quarkus.vertx.http.runtime.security.HttpCredentialTransport;
import io.quarkus.vertx.http.runtime.security.HttpSecurityUtils;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

public class MfaAuthenticationMechanism implements HttpAuthenticationMechanism {

	private static final Logger log = Logger.getLogger(MfaAuthenticationMechanism.class);

	private final String loginView;
	private final String logoutView;
	private final String loginAction;
	private final JWELoginManager loginManager;

	MfaAuthenticationMechanism(String loginView, String logoutView, String loginAction, JWELoginManager loginManager) {
		this.loginView = loginView;
		this.logoutView = logoutView;
		this.loginAction = loginAction;
		this.loginManager = loginManager;
	}

	@Override
	public Uni<SecurityIdentity> authenticate(RoutingContext context, IdentityProviderManager identityProviderManager) {
		String path = context.request().path();
		log.infof("authenticating %s", path);
		JwtClaims claims = loginManager.restore(context);
		if (loginManager.hasSubject(claims)) {
			return restoreIdentity(claims, context, identityProviderManager);
		}		
		if (this.loginView.equals(path)) {
			return prepareLoginView(claims, context, identityProviderManager);
		}
		if (this.loginAction.equals(path)) {
			return prepareLoginAction(claims, context, identityProviderManager);
		}
		if (this.logoutView.equals(path)) {
			return prepareLoginView(claims, context, identityProviderManager);
		}
		return Uni.createFrom().nullItem();
	}

	public Uni<SecurityIdentity> restoreIdentity(JwtClaims claims, RoutingContext context, IdentityProviderManager identityProviderManager) {
		// previously authenticated. Automatically login using trusted credentials
		context.put(HttpAuthenticationMechanism.class.getName(), this);
		Uni<SecurityIdentity> ret = identityProviderManager.authenticate(HttpSecurityUtils.setRoutingContextAttribute(new MfaAuthenticationRequest(claims), context));
		return ret.onItem().invoke(new Consumer<SecurityIdentity>() {
			@Override
			public void accept(SecurityIdentity securityIdentity) {
				if (loginManager.newCookieNeeded(claims)) {
					loginManager.save(claims, context, context.request().isSSL());
				}
			}
		});
	}

	public Uni<SecurityIdentity> prepareLoginView(JwtClaims claims, RoutingContext context, IdentityProviderManager identityProviderManager) {
		System.out.format("Prepare Login View Invoked\n");
		return identityProviderManager.authenticate(AnonymousAuthenticationRequest.INSTANCE);
	}

	public Uni<SecurityIdentity> prepareLoginAction(JwtClaims claims, RoutingContext context, IdentityProviderManager identityProviderManager) {
		System.out.format("Prepare Login Action Invoked\n");
		return identityProviderManager.authenticate(AnonymousAuthenticationRequest.INSTANCE);
	}

	public Uni<SecurityIdentity> prepareLogoutView(JwtClaims claims, RoutingContext context, IdentityProviderManager identityProviderManager) {
		System.out.format("Prepare Logout View Invoked\n");
		return identityProviderManager.authenticate(AnonymousAuthenticationRequest.INSTANCE);
	}

	public void action(RoutingContext ctx) {
		System.out.format("Login Action Invoked\n");
	}

	@Override
	public Uni<ChallengeData> getChallenge(RoutingContext context) {
		log.debugf("Serving login form %s for %s", loginView, context);
		return getRedirect(context, loginView);
	}

	static Uni<ChallengeData> getRedirect(final RoutingContext exchange, final String location) {
		String loc = exchange.request().scheme() + "://" + exchange.request().host() + location;
		return Uni.createFrom().item(new ChallengeData(302, "Location", loc));
	}

	@Override
	public Set<Class<? extends AuthenticationRequest>> getCredentialTypes() {
		return new HashSet<>(Arrays.asList(MfaAuthenticationRequest.class));
	}

	@Override
	public Uni<HttpCredentialTransport> getCredentialTransport(RoutingContext context) {
		return Uni.createFrom().nullItem();
	}

}

package io.github.aaronanderson.quarkus.mfa.runtime;

import static io.vertx.core.http.HttpHeaders.CACHE_CONTROL;
import static io.vertx.core.http.HttpHeaders.LOCATION;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

import org.jboss.logging.Logger;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;

import io.github.aaronanderson.quarkus.mfa.runtime.MfaIdentityStore.AuthenticationResult;
import io.quarkus.arc.Arc;
import io.quarkus.security.credential.PasswordCredential;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.AnonymousAuthenticationRequest;
import io.quarkus.security.identity.request.AuthenticationRequest;
import io.quarkus.vertx.http.runtime.security.ChallengeData;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism;
import io.quarkus.vertx.http.runtime.security.HttpCredentialTransport;
import io.quarkus.vertx.http.runtime.security.HttpSecurityUtils;
import io.smallrye.mutiny.Uni;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.ext.web.RoutingContext;

public class MfaAuthenticationMechanism implements HttpAuthenticationMechanism {

	private static final Logger log = Logger.getLogger(MfaAuthenticationMechanism.class);

	public static final String AUTH_CONTEXT_KEY = "quarkus_mfa_auth_context";

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
		System.out.format("restored claims %s\n", claims);
		if (loginManager.hasSubject(claims)) {
			return restoreIdentity(claims, context, identityProviderManager);
		}
		if (claims == null || loginManager.newCookieNeeded(claims)) {
			claims = new JwtClaims();
		}
		context.put(AUTH_CONTEXT_KEY, claims);

		if (loginView.equals(path)) {
			claims.setClaim("action", "login");
			loginManager.save(claims, context, context.request().isSSL());
		} else if (logoutView.equals(path)) {
			claims.setClaim("action", "logout");
			loginManager.clear(context);
		} else if (loginAction.equals(path)) {
			if (!claims.hasClaim("action")) { //zero form login
				claims.setClaim("action", "login");
				claims.setClaim("path", "/");
			}
		} else {
			claims.setClaim("path", path);
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

	public Uni<SecurityIdentity> prepareLogoutView(JwtClaims claims, RoutingContext context, IdentityProviderManager identityProviderManager) {
		System.out.format("Prepare Logout View Invoked\n");
		return identityProviderManager.authenticate(AnonymousAuthenticationRequest.INSTANCE);
	}

	public void action(RoutingContext context) {
		MfaIdentityStore mfaIdentityStore = Arc.container().instance(MfaIdentityStore.class).get();
		JwtClaims authContext = context.get(AUTH_CONTEXT_KEY);
		System.out.format("Login Action Invoked %s\n", authContext);
		System.out.format("Identity Store%s\n", mfaIdentityStore);
		if ("login".equals(authContext.getClaimValueAsString("action"))) {
			handleLogin(context, authContext, mfaIdentityStore);
		} else {
			HttpServerResponse response = context.response();
			response.setStatusCode(500);
			response.setStatusMessage("unexpected state");
			context.response().end();
		}

//		response.setChunked(true);
//		response.putHeader(CACHE_CONTROL, "no-store, no-cache, no-transform, must-revalidate, max-age=0");
//		response.write("Login Action");
//		context.response().end();

	}

	private void handleLogin(RoutingContext context, JwtClaims authContext, MfaIdentityStore mfaIdentityStore) {
		System.out.format("Performing Login\n");
		Map<String, Object> attributes = new HashMap<>();
		String username = context.request().getFormAttribute("username");
		String password = context.request().getFormAttribute("password");
		if (username != null && password != null) {
			AuthenticationResult authResult = mfaIdentityStore.authenticate(username, new PasswordCredential(password.toCharArray()), attributes);
			if (authResult == AuthenticationResult.SUCCESS) {
				JwtClaims authenticated = new JwtClaims();
				authenticated.setIssuedAt(NumericDate.now());
				attributes.entrySet().forEach(e -> authenticated.setClaim(e.getKey(), e.getValue()));
				System.out.format("Login Success %s\n", authenticated);
				loginManager.save(authenticated, context, context.request().isSSL());
				sendRedirect(context, authContext.getClaimValueAsString("path"));
			} else {
				authContext.setClaim("status", "failed");
				loginManager.save(authContext, context, context.request().isSSL());
				sendRedirect(context, loginView);
			}

		}
	}

	@Override
	public Uni<ChallengeData> getChallenge(RoutingContext context) {
		log.debugf("Serving login form %s for %s", loginView, context);
		JwtClaims authContext = context.get(AUTH_CONTEXT_KEY);
		loginManager.save(authContext, context, context.request().isSSL());
		return getChallengeRedirect(context, loginView);
	}

	static Uni<ChallengeData> getChallengeRedirect(final RoutingContext exchange, final String location) {
		String loc = exchange.request().scheme() + "://" + exchange.request().host() + location;
		return Uni.createFrom().item(new ChallengeData(302, LOCATION, loc));
	}

	static void sendRedirect(final RoutingContext exchange, final String location) {
		String loc = exchange.request().scheme() + "://" + exchange.request().host() + location;
		exchange.response().setStatusCode(302).putHeader(LOCATION, loc).end();
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

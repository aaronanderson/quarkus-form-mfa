package io.github.aaronanderson.quarkus.mfa.runtime;

import static io.github.aaronanderson.quarkus.mfa.runtime.MfaAuthContext.AUTH_ACTION_KEY;
import static io.github.aaronanderson.quarkus.mfa.runtime.MfaAuthContext.AUTH_CLAIMS_KEY;
import static io.github.aaronanderson.quarkus.mfa.runtime.MfaAuthContext.AUTH_STATUS_KEY;
import static io.github.aaronanderson.quarkus.mfa.runtime.MfaAuthContext.AUTH_TOTP_URL_KEY;
import static io.vertx.core.http.HttpHeaders.LOCATION;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

import org.jboss.logging.Logger;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;

import com.j256.twofactorauth.TimeBasedOneTimePasswordUtil;

import io.github.aaronanderson.quarkus.mfa.runtime.MfaAuthContext.FormFields;
import io.github.aaronanderson.quarkus.mfa.runtime.MfaAuthContext.ViewAction;
import io.github.aaronanderson.quarkus.mfa.runtime.MfaAuthContext.ViewStatus;
import io.github.aaronanderson.quarkus.mfa.runtime.MfaIdentityStore.AuthenticationResult;
import io.github.aaronanderson.quarkus.mfa.runtime.MfaIdentityStore.PasswordResetResult;
import io.github.aaronanderson.quarkus.mfa.runtime.MfaIdentityStore.TotpCallback;
import io.github.aaronanderson.quarkus.mfa.runtime.MfaIdentityStore.VerificationResult;
import io.quarkus.arc.Arc;
import io.quarkus.security.credential.PasswordCredential;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
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
		log.debugf("authenticating %s", path);
		JwtClaims claims = loginManager.restore(context);
		if (loginManager.hasSubject(claims) && !logoutView.equals(path)) {
			return restoreIdentity(claims, context, identityProviderManager);
		}
		if (claims == null || loginManager.newCookieNeeded(claims)) {
			claims = new JwtClaims();
		}
		context.put(AUTH_CLAIMS_KEY, claims);

		if (loginView.equals(path)) {
			if (!claims.hasClaim("action")) {
				claims.setClaim("action", ViewAction.LOGIN);
			}
			context.put(AUTH_ACTION_KEY, ViewAction.get(claims.getClaimValueAsString("action")));
			context.put(AUTH_STATUS_KEY, ViewStatus.get(claims.getClaimValueAsString("status")));
			if (claims.hasClaim("totp-url")) {
				context.put(AUTH_TOTP_URL_KEY, claims.getClaimValueAsString("totp-url"));
			}
			loginManager.save(claims, context);
		} else if (logoutView.equals(path)) {
			if (!claims.hasClaim("action")) {
				claims.setClaim("action", ViewAction.LOGOUT.toString());
			}
			context.put(AUTH_ACTION_KEY, ViewAction.get(claims.getClaimValueAsString("action")));
			loginManager.clear(context);
		} else if (loginAction.equals(path)) {
			if (!claims.hasClaim("action")) { // zero form login
				claims.setClaim("action", ViewAction.LOGIN.toString());
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
					loginManager.save(claims, context);
				}
			}
		});
	}

	public void action(RoutingContext context) {
		MfaIdentityStore mfaIdentityStore = Arc.container().instance(MfaIdentityStore.class).get();
		JwtClaims authContext = context.get(AUTH_CLAIMS_KEY);
		ViewAction action = ViewAction.get(authContext.getClaimValueAsString("action"));
		if (ViewAction.LOGIN == action) {
			handleLogin(context, authContext, mfaIdentityStore);
		} else if (ViewAction.PASSWORD_RESET == action) {
			handlePasswordReset(context, authContext, mfaIdentityStore);
		} else if (ViewAction.VERIFY_TOTP == action) {
			handleVerifyTotp(context, authContext, mfaIdentityStore);
		} else if (ViewAction.REGISTER_TOTP == action) {
			if (context.request().getParam(FormFields.PASSCODE.toString()) != null) {
				// allow zero page/direct passcode verification after registration
				authContext.setClaim("action", ViewAction.VERIFY_TOTP);
				handleVerifyTotp(context, authContext, mfaIdentityStore);
			} else {
				handleRegisterTotp(context, authContext, mfaIdentityStore);
			}
		} else {
			HttpServerResponse response = context.response();
			response.setStatusCode(500);
			log.errorf("unexpected state %s", authContext.getClaimValueAsString("action"));
			response.setStatusMessage("unexpected state");
			context.response().end();
		}

//		response.setChunked(true);
//		response.putHeader(CACHE_CONTROL, "no-store, no-cache, no-transform, must-revalidate, max-age=0");
//		response.write("Login Action");
//		context.response().end();

	}

	private void successfulLogin(RoutingContext context, JwtClaims authContext, Map<String, Object> attributes) {
		String path = authContext.getClaimValueAsString("path");
		JwtClaims authenticated = new JwtClaims();
		authenticated.setIssuedAt(NumericDate.now());
		attributes.entrySet().forEach(e -> authenticated.setClaim(e.getKey(), e.getValue()));
		if (!authenticated.hasClaim("sub")) {
			log.errorf("Mandatory subject claim 'sub' not set by identity store");
		}
		if (log.isDebugEnabled()) {
			log.debugf("login success - path: %s claims: %s ", path, authenticated.toJson());
		}
		loginManager.save(authenticated, context);
		sendRedirect(context, path);
	}

	private void handleLogin(RoutingContext context, JwtClaims authContext, MfaIdentityStore mfaIdentityStore) {
		log.debugf("processing login");
		Map<String, Object> attributes = new HashMap<>();
		String username = context.request().getFormAttribute(FormFields.USERNAME.toString());
		String password = context.request().getFormAttribute(FormFields.PASSWORD.toString());
		if (username == null || password == null) {
			loginRedirect(context, authContext);
		} else {
			AuthenticationResult authResult = mfaIdentityStore.authenticate(username, new PasswordCredential(password.toCharArray()), attributes);
			if (authResult == AuthenticationResult.SUCCESS) {
				successfulLogin(context, authContext, attributes);
			} else {
				if (authResult == AuthenticationResult.SUCCESS_VERIFY_TOTP) {
					authContext.setClaim("action", ViewAction.VERIFY_TOTP);
					authContext.setClaim("auth-sub", username);
					authContext.unsetClaim("status");
					log.debugf("login success - verify TOTP");
				} else if (authResult == AuthenticationResult.SUCCESS_REGISTER_TOTP) {
					registerTotp(username, authContext, mfaIdentityStore);
					log.debugf("login success - register TOTP");
				} else if (authResult == AuthenticationResult.SUCCESS_RESET_PASSWORD) {
					authContext.setClaim("action", ViewAction.PASSWORD_RESET);
					authContext.setClaim("auth-sub", username);
					authContext.unsetClaim("status");
					log.debugf("login success - password reset");
				} else if (authResult == AuthenticationResult.FAILED_ACCOUNT_LOCKED) {
					authContext.setClaim("status", ViewStatus.ACCOUNT_LOCKED);
					log.debugf("login failed - account locekd");
				} else if (authResult == AuthenticationResult.FAILED) {
					authContext.setClaim("status", ViewStatus.FAILED);
					log.debugf("login failed");
				}
				if (log.isDebugEnabled()) {
					log.debugf("login redirect claims: %s", authContext.toJson());
				}
				loginManager.save(authContext, context);
				sendRedirect(context, loginView);
			}

		}

	}

	private void registerTotp(String username, JwtClaims authContext, MfaIdentityStore mfaIdentityStore) {
		authContext.setClaim("action", ViewAction.REGISTER_TOTP);
		authContext.setClaim("auth-sub", username);
		String base32Secret = TimeBasedOneTimePasswordUtil.generateBase32Secret();
		String keyId = mfaIdentityStore.storeTotpKey(username, new PasswordCredential(base32Secret.toCharArray()));
		String imageURL = TimeBasedOneTimePasswordUtil.qrImageUrl(keyId, base32Secret);
		authContext.setClaim("totp-url", imageURL);
		authContext.unsetClaim("status");

	}

	private void loginRedirect(RoutingContext context, JwtClaims authContext) {
		authContext.setClaim("action", ViewAction.LOGIN);
		authContext.unsetClaim("status");
		loginManager.save(authContext, context);
		sendRedirect(context, loginView);

	}

	private void handlePasswordReset(RoutingContext context, JwtClaims authContext, MfaIdentityStore mfaIdentityStore) {
		log.debugf("processing password reset");
		String username = authContext.getClaimValueAsString("auth-sub");
		String currentPassword = context.request().getFormAttribute(FormFields.PASSWORD.toString());
		String newPassword = context.request().getFormAttribute(FormFields.NEW_PASSWORD.toString());
		if (username == null || currentPassword == null || newPassword == null) {
			loginRedirect(context, authContext);
		} else {
			Map<String, Object> attributes = new HashMap<>();
			PasswordResetResult authResult = mfaIdentityStore.passwordReset(username, new PasswordCredential(currentPassword.toCharArray()), new PasswordCredential(newPassword.toCharArray()), attributes);
			if (authResult == PasswordResetResult.SUCCESS) {
				successfulLogin(context, authContext, attributes);
			} else {
				if (authResult == PasswordResetResult.SUCCESS_VERIFY_TOTP) {
					authContext.setClaim("action", ViewAction.VERIFY_TOTP);
					authContext.setClaim("auth-sub", username);
					authContext.unsetClaim("status");
					log.debugf("password reset success - verify TOTP");
				} else if (authResult == PasswordResetResult.SUCCESS_REGISTER_TOTP) {
					registerTotp(username, authContext, mfaIdentityStore);
					log.debugf("password reset success - register TOTP");
				} else if (authResult == PasswordResetResult.FAILED_CURRENT) {
					authContext.setClaim("status", ViewStatus.FAILED_CURRENT);
					log.debugf("password reset failed - current password");
				} else if (authResult == PasswordResetResult.FAILED_POLICY) {
					authContext.setClaim("status", ViewStatus.FAILED_POLICY);
					log.debugf("password reset failed - password policy");
				}
				loginManager.save(authContext, context);
				sendRedirect(context, loginView);
			}
		}
	}

	private void handleVerifyTotp(RoutingContext context, JwtClaims authContext, MfaIdentityStore mfaIdentityStore) {
		log.debugf("processing verify TOTP");
		String username = authContext.getClaimValueAsString("auth-sub");
		String passcode = context.request().getFormAttribute(FormFields.PASSCODE.toString());
		if (username == null || passcode == null) {
			loginRedirect(context, authContext);
		} else {
			Map<String, Object> attributes = new HashMap<>();
			TotpCallback callback = p -> {
				try {
					String currentPasscode = TimeBasedOneTimePasswordUtil.generateCurrentNumberString(new String(p.getPassword()));
					return currentPasscode.equals(passcode);
				} catch (GeneralSecurityException e) {
					log.errorf(e, "passcode error");
					return false;
				}

			};
			VerificationResult authResult = mfaIdentityStore.verifyTotp(username, callback, attributes);
			if (authResult == VerificationResult.SUCCESS) {
				successfulLogin(context, authContext, attributes);
			} else {
				if (authResult == VerificationResult.FAILED) {
					authContext.setClaim("status", ViewStatus.FAILED);
				}
				loginManager.save(authContext, context);
				sendRedirect(context, loginView);
			}
		}
	}

	private void handleRegisterTotp(RoutingContext context, JwtClaims authContext, MfaIdentityStore mfaIdentityStore) {
		log.debugf("processing register TOTP"); // redirect back to login page. Could be handled client side as well
		String username = authContext.getClaimValueAsString("auth-sub");
		if (username == null) {
			loginRedirect(context, authContext);
		} else {
			authContext.setClaim("action", ViewAction.VERIFY_TOTP);
			authContext.unsetClaim("status");
			authContext.unsetClaim("totp-url");
			loginManager.save(authContext, context);
			sendRedirect(context, loginView);
		}
	}

	@Override
	public Uni<ChallengeData> getChallenge(RoutingContext context) {
		log.debugf("Serving login form %s for %s", loginView, context);
		JwtClaims authContext = context.get(AUTH_CLAIMS_KEY);
		loginManager.save(authContext, context);
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

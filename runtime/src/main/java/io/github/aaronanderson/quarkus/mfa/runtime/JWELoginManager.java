package io.github.aaronanderson.quarkus.mfa.runtime;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import org.jboss.logging.Logger;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;

import io.vertx.core.http.Cookie;
import io.vertx.ext.web.RoutingContext;

public class JWELoginManager {

	private static final Logger log = Logger.getLogger(JWELoginManager.class);

	private final SecretKey secretKey;
	private final String cookieName;
	private final long timeoutMillis;
	private final long newCookieIntervalMillis;

	public JWELoginManager(SecretKey jweKey, String cookieName, long timeoutMillis, long newCookieIntervalMillis) {
		this.secretKey = jweKey;
		this.cookieName = cookieName;
		this.newCookieIntervalMillis = newCookieIntervalMillis;
		this.timeoutMillis = timeoutMillis;
	}

	public JwtClaims restore(RoutingContext context) {
		return restore(context, cookieName);
	}

	public JwtClaims restore(RoutingContext context, String cookieName) {
		Cookie existing = context.request().getCookie(cookieName);
		// If there is no credential cookie, we have nothing to restore.
		if (existing == null) {
			// Enforce new login.
			return null;
		}
		String serializedJwe = existing.getValue();
		System.out.format("received cookie %s - %s\n", cookieName, serializedJwe);
		try {
			JsonWebEncryption jwe = new JsonWebEncryption();
			jwe.setAlgorithmConstraints(new AlgorithmConstraints(ConstraintType.PERMIT, KeyManagementAlgorithmIdentifiers.A128KW));
			jwe.setContentEncryptionAlgorithmConstraints(new AlgorithmConstraints(ConstraintType.PERMIT, ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256));
			jwe.setKey(secretKey);
			jwe.setCompactSerialization(serializedJwe);
			JwtClaims claims = JwtClaims.parse(jwe.getPayload());
			if (isExpired(claims)) {
				return null;
			}
			return claims;
		} catch (Exception e) {
			log.debug("Failed to restore persistent user session", e);
			return null;
		}
	}

	public boolean hasSubject(JwtClaims claims) {
		try {
			return claims != null && claims.getSubject() != null;
		} catch (MalformedClaimException e) {
			return false;
		}

	}

	public boolean isExpired(JwtClaims claims) {
		try {
			long expirationTime = claims.getExpirationTime().getValueInMillis();
			long now = System.currentTimeMillis();
			boolean expired = expirationTime < now;
			log.infof("Is expired? ( %d - %d : %b", expirationTime, now, (Boolean) expired);
			return expired;
		} catch (MalformedClaimException e) {
			return true;
		}

	}

	public boolean newCookieNeeded(JwtClaims claims) {
		try {
			long expireIdle = claims.getExpirationTime().getValue();
			long now = System.currentTimeMillis();
			log.debugf("Current time: %s, Expire idle timeout: %s, expireIdle - now is: %d - %d = %d", new Date(now).toString(), new Date(expireIdle).toString(), expireIdle, now, expireIdle - now);
			boolean newCookieNeeded = (timeoutMillis - (expireIdle - now)) > newCookieIntervalMillis;
			log.debugf("Is new cookie needed? ( %d - ( %d - %d)) > %d : %b", timeoutMillis, expireIdle, now, newCookieIntervalMillis, newCookieNeeded);
			return newCookieNeeded;
		} catch (MalformedClaimException e) {
			return true;
		}
	}

	public void save(JwtClaims claims, RoutingContext context, boolean secureCookie) {
		save(claims, context, cookieName, secureCookie);
	}

	public void save(JwtClaims claims, RoutingContext context, String cookieName, boolean secureCookie) {
		try {
			long timeout = System.currentTimeMillis() + timeoutMillis;
			log.infof("The new cookie will expire at %s", new Date(timeout).toString());
			claims.setExpirationTime(NumericDate.fromMilliseconds(timeout));

			JsonWebEncryption jwe = new JsonWebEncryption();
			jwe.setPayload(claims.toJson());
			jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.A128KW);
			jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
			jwe.setKey(secretKey);
			String cookieValue = jwe.getCompactSerialization();
			System.out.format("adding cookie %s - %s\n", cookieName, cookieValue);
			context.response().addCookie(Cookie.cookie(cookieName, cookieValue).setPath("/").setSecure(secureCookie));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}

	}

	public void clear(RoutingContext ctx) {
		// Vert.x sends back a set-cookie with max-age and expiry but no path, so we have to set it first,
		// otherwise web clients don't clear it
		Cookie cookie = ctx.request().getCookie(cookieName);
		if (cookie != null) {
			cookie.setPath("/");
		}
		ctx.response().removeCookie(cookieName);
	}

	public static class RestoreResult {

		private final String principal;
		final boolean newCookieNeeded;

		public RestoreResult(String principal, boolean newCookieNeeded) {
			this.principal = principal;
			this.newCookieNeeded = newCookieNeeded;
		}

		public String getPrincipal() {
			return principal;
		}
	}

}

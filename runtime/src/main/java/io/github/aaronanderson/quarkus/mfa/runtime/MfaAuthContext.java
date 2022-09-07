package io.github.aaronanderson.quarkus.mfa.runtime;

import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class MfaAuthContext {
	public static final String AUTH_CLAIMS_KEY = "quarkus_mfa_auth_claims";
	public static final String AUTH_ACTION_KEY = "quarkus_mfa_auth_action";
	public static final String AUTH_STATUS_KEY = "quarkus_mfa_auth_status";
	public static final String AUTH_TOTP_URL_KEY = "quarkus_mfa_auth_topt_url";

	public static enum ViewAction {

		LOGIN("login"), LOGOUT("logout"), PASSWORD_RESET("password-reset"), VERIFY_TOTP("verify-totp"), REGISTER_TOTP("register-totp");

		private static final Map<String, ViewAction> ENUM_MAP;
		static {
			ENUM_MAP = Stream.of(ViewAction.values()).collect(Collectors.toMap(Enum::toString, Function.identity()));
		}

		private final String text;

		ViewAction(final String text) {
			this.text = text;
		}

		@Override
		public String toString() {
			return text;
		}

		public static ViewAction get(String name) {
			return name != null ? ENUM_MAP.get(name.toLowerCase()) : null;
		}

	}

	public static enum ViewStatus {
		ACCOUNT_LOCKED("account-locked"), FAILED("failed"), FAILED_CURRENT("failed-current"), FAILED_POLICY("failed-policy");

		private static final Map<String, ViewStatus> ENUM_MAP;
		static {
			ENUM_MAP = Stream.of(ViewStatus.values()).collect(Collectors.toMap(Enum::toString, Function.identity()));
		}

		private final String text;

		ViewStatus(final String text) {
			this.text = text;
		}

		@Override
		public String toString() {
			return text;
		}

		public static ViewStatus get(String name) {
			return name != null ? ENUM_MAP.get(name.toLowerCase()) : null;
		}

	}

	public static enum FormFields {
		USERNAME("username"), PASSWORD("password"), NEW_PASSWORD("new-password"), PASSCODE("passcode");

		private static final Map<String, FormFields> ENUM_MAP;
		static {
			ENUM_MAP = Stream.of(FormFields.values()).collect(Collectors.toMap(Enum::toString, Function.identity()));
		}

		private final String text;

		FormFields(final String text) {
			this.text = text;
		}

		@Override
		public String toString() {
			return text;
		}

		public static FormFields get(String name) {
			return name != null ? ENUM_MAP.get(name.toLowerCase()) : null;
		}

	}

}

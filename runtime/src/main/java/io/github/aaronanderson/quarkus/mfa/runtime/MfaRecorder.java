package io.github.aaronanderson.quarkus.mfa.runtime;

import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

import javax.crypto.SecretKey;

import org.jboss.logging.Logger;
import org.jose4j.keys.AesKey;
import org.jose4j.lang.ByteUtil;

import io.quarkus.arc.Arc;
import io.quarkus.arc.InstanceHandle;
import io.quarkus.arc.runtime.BeanContainer;
import io.quarkus.runtime.RuntimeValue;
import io.quarkus.runtime.annotations.Recorder;
import io.quarkus.vertx.http.runtime.HttpBuildTimeConfig;
import io.quarkus.vertx.http.runtime.PolicyMappingConfig;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;

@Recorder
public class MfaRecorder {

	private static final Logger log = Logger.getLogger(MfaRecorder.class);

	final RuntimeValue<MfaRunTimeConfig> config;
	//final HttpBuildTimeConfig httpBuildTimeConfig;

	// the temp encryption key, persistent across dev mode restarts
	static volatile String encryptionKey;

	public MfaRecorder(RuntimeValue<MfaRunTimeConfig> config) {		
		this.config = config;
		//this.httpBuildTimeConfig = httpBuildTimeConfig;
	}
	
	//automatically add MFA endpoints to the authentication policy to allow anonymous access.
	public void initPermissions(MfaBuildTimeConfig mfaBuildTimeConfig, HttpBuildTimeConfig httpBuildTimeConfig) {
    	PolicyMappingConfig config = new PolicyMappingConfig();
    	config.enabled= Optional.of(true);
    	config.methods = Optional.of(List.of("GET", "POST"));
    	config.paths = Optional.of(List.of(mfaBuildTimeConfig.loginView, mfaBuildTimeConfig.logoutView,mfaBuildTimeConfig.loginAction ));
    	config.policy= "permit";
    	config.authMechanism= Optional.empty();
    	httpBuildTimeConfig.auth.permissions.put("quarkus_mfa", config);

	}

	public void setupRoutes(BeanContainer beanContainer, MfaBuildTimeConfig buildConfig, RuntimeValue<Router> routerValue) {
		//MfaRunTimeConfig config = MfaRecorder.this.config.getValue();
		System.out.format("setupRoutes %s\n", buildConfig);
		MfaAuthenticationMechanism authMech = beanContainer.instance(MfaAuthenticationMechanism.class);
		Router router = routerValue.getValue();
		BodyHandler bodyHandler = BodyHandler.create();
		String loginAction = buildConfig.loginAction.startsWith("/") ? buildConfig.loginAction : "/" + buildConfig.loginAction;
		router.post(loginAction).handler(bodyHandler).handler(authMech::action);
	}

	public Supplier<MfaAuthenticationMechanism> setupMfaAuthenticationMechanism(MfaBuildTimeConfig buildConfig) {    	
		System.out.format("setupMfaAuthenticationMechanism %s\n", buildConfig);
		//MfaIdentityStore identityStore = beanContainer.instance(MfaIdentityStore.class);
		return new Supplier<MfaAuthenticationMechanism>() {
			@Override
			public MfaAuthenticationMechanism get() {
				String key;
				if (!config.getValue().encryptionKey.isPresent()) {
					if (encryptionKey != null) {
						// persist across dev mode restarts
						key = encryptionKey;
					} else {
						byte[] data = ByteUtil.randomBytes(16);
						key = encryptionKey = Base64.getEncoder().encodeToString(data);
						log.warn("Encryption key was not specified for persistent MFA auth, using temporary key " + key);
					}
				} else {
					key = config.getValue().encryptionKey.get();
				}
				SecretKey jweKey = new AesKey(Base64.getDecoder().decode(key));
				MfaRunTimeConfig config = MfaRecorder.this.config.getValue();
				JWELoginManager loginManager = new JWELoginManager(jweKey, config.cookieName, config.sessionTimeout.toMillis(), config.newCookieInterval.toMillis());
				String loginView = buildConfig.loginView.startsWith("/") ? buildConfig.loginView : "/" + buildConfig.loginView;
				String logoutView = buildConfig.logoutView.startsWith("/") ? buildConfig.logoutView : "/" + buildConfig.logoutView;
				String loginAction = buildConfig.loginAction.startsWith("/") ? buildConfig.loginAction : "/" + buildConfig.loginAction;
				return new MfaAuthenticationMechanism(loginView, logoutView, loginAction, loginManager);
			}
		};
	}

}

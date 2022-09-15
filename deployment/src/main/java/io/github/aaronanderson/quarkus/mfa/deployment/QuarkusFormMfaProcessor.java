package io.github.aaronanderson.quarkus.mfa.deployment;

import java.util.function.BooleanSupplier;

import javax.inject.Singleton;

import io.github.aaronanderson.quarkus.mfa.runtime.FormMfaAuthenticationMechanism;
import io.github.aaronanderson.quarkus.mfa.runtime.FormMfaBuildTimeConfig;
import io.github.aaronanderson.quarkus.mfa.runtime.FormMfaIdentityProvider;
import io.github.aaronanderson.quarkus.mfa.runtime.FormMfaRecorder;
import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.arc.deployment.BeanContainerBuildItem;
import io.quarkus.arc.deployment.SyntheticBeanBuildItem;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.BuildSteps;
import io.quarkus.deployment.annotations.ExecutionTime;
import io.quarkus.deployment.annotations.Record;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.vertx.http.deployment.VertxWebRouterBuildItem;
import io.quarkus.vertx.http.runtime.HttpBuildTimeConfig;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism;

@BuildSteps(onlyIf = QuarkusFormMfaProcessor.IsEnabled.class)
class QuarkusFormMfaProcessor {

	private static final String FEATURE = "mfa";

	@BuildStep
	FeatureBuildItem feature() {
		return new FeatureBuildItem(FEATURE);
	}

	@BuildStep
	public void myBeans(BuildProducer<AdditionalBeanBuildItem> additionalBeans) {
		AdditionalBeanBuildItem.Builder builder = AdditionalBeanBuildItem.builder();
		builder.addBeanClass(FormMfaIdentityProvider.class);
		additionalBeans.produce(builder.build());
	}

	@BuildStep
	@Record(ExecutionTime.STATIC_INIT)
	public void initPermissions(FormMfaRecorder recorder, FormMfaBuildTimeConfig mfaBuildTimeConfig, HttpBuildTimeConfig httpBuildTimeConfig) {
		recorder.initPermissions(mfaBuildTimeConfig, httpBuildTimeConfig);

	}

	@Record(ExecutionTime.RUNTIME_INIT)
	@BuildStep
	public void setup(FormMfaRecorder recorder, FormMfaBuildTimeConfig mfaBuildTimeConfig, VertxWebRouterBuildItem vertxWebRouterBuildItem, BeanContainerBuildItem beanContainerBuildItem) {
		recorder.setupRoutes(beanContainerBuildItem.getValue(), mfaBuildTimeConfig, vertxWebRouterBuildItem.getHttpRouter());
	}

	@BuildStep
	@Record(ExecutionTime.RUNTIME_INIT)
	void initMfaAuth(FormMfaRecorder recorder, FormMfaBuildTimeConfig mfaBuildTimeConfig, BuildProducer<SyntheticBeanBuildItem> syntheticBeans) {
		syntheticBeans.produce(SyntheticBeanBuildItem.configure(FormMfaAuthenticationMechanism.class).unremovable().types(HttpAuthenticationMechanism.class).setRuntimeInit().scope(Singleton.class).supplier(recorder.setupMfaAuthenticationMechanism(mfaBuildTimeConfig)).done());
	}

	public static class IsEnabled implements BooleanSupplier {
		FormMfaBuildTimeConfig config;

		public boolean getAsBoolean() {
			return config.enabled;
		}
	}
}

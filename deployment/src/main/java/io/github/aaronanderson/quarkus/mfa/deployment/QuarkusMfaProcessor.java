package io.github.aaronanderson.quarkus.mfa.deployment;

import java.util.List;
import java.util.Optional;
import java.util.function.BooleanSupplier;

import javax.inject.Singleton;

import io.github.aaronanderson.quarkus.mfa.runtime.MfaAuthenticationMechanism;
import io.github.aaronanderson.quarkus.mfa.runtime.MfaBuildTimeConfig;
import io.github.aaronanderson.quarkus.mfa.runtime.MfaIdentityProvider;
import io.github.aaronanderson.quarkus.mfa.runtime.MfaRecorder;
import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.arc.deployment.BeanContainerBuildItem;
import io.quarkus.arc.deployment.SyntheticBeanBuildItem;
import io.quarkus.builder.item.EmptyBuildItem;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.BuildSteps;
import io.quarkus.deployment.annotations.ExecutionTime;
import io.quarkus.deployment.annotations.Produce;
import io.quarkus.deployment.annotations.Record;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.vertx.http.deployment.VertxWebRouterBuildItem;
import io.quarkus.vertx.http.runtime.HttpBuildTimeConfig;
import io.quarkus.vertx.http.runtime.PolicyMappingConfig;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism;

@BuildSteps(onlyIf = QuarkusMfaProcessor.IsEnabled.class)
class QuarkusMfaProcessor {

    private static final String FEATURE = "mfa";

    @BuildStep
    FeatureBuildItem feature() {
        return new FeatureBuildItem(FEATURE);
    }
    
    
    @BuildStep
    public void myBeans(BuildProducer<AdditionalBeanBuildItem> additionalBeans) {
        AdditionalBeanBuildItem.Builder builder = AdditionalBeanBuildItem.builder().setUnremovable();
        builder.addBeanClass(MfaIdentityProvider.class);
        additionalBeans.produce(builder.build());
    }

    @BuildStep
    @Produce(EmptyBuildItem.class) 
    public void initPermissions(
    		MfaBuildTimeConfig mfaBuildTimeConfig,
            HttpBuildTimeConfig httpBuildTimeConfig) {
    	System.out.format("initPermissions %s\n", mfaBuildTimeConfig);
    	PolicyMappingConfig config = new PolicyMappingConfig();
    	config.methods = Optional.of(List.of("GET", "POST"));
    	config.paths = Optional.of(List.of(mfaBuildTimeConfig.loginView, mfaBuildTimeConfig.logoutView,mfaBuildTimeConfig.loginAction ));
    	config.policy= "permit";
    	httpBuildTimeConfig.auth.permissions.put("quarkus_mfa", config);
        
    }
    
    @Record(ExecutionTime.RUNTIME_INIT)
    @BuildStep
    public void setup(
            MfaRecorder recorder,
            MfaBuildTimeConfig mfaBuildTimeConfig,
            VertxWebRouterBuildItem vertxWebRouterBuildItem,
            BeanContainerBuildItem beanContainerBuildItem) {
        recorder.setupRoutes(beanContainerBuildItem.getValue(), mfaBuildTimeConfig, vertxWebRouterBuildItem.getHttpRouter());
    }

 

    @BuildStep
    @Record(ExecutionTime.RUNTIME_INIT)
    SyntheticBeanBuildItem initMfaAuth(
            MfaRecorder recorder,
            MfaBuildTimeConfig mfaBuildTimeConfig) {
        return SyntheticBeanBuildItem.configure(MfaAuthenticationMechanism.class)
                .types(HttpAuthenticationMechanism.class)
                .setRuntimeInit()
                .scope(Singleton.class)
                .supplier(recorder.setupMfaAuthenticationMechanism(mfaBuildTimeConfig)).done();
    }
    
    public static class IsEnabled implements BooleanSupplier {
        MfaBuildTimeConfig config;

        public boolean getAsBoolean() {
            return config.enabled;
        }
    }
}

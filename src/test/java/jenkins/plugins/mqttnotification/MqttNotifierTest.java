package jenkins.plugins.mqttnotification;

import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import hudson.EnvVars;
import hudson.model.FreeStyleBuild;
import hudson.model.FreeStyleProject;
import hudson.model.Item;
import hudson.model.Queue;
import hudson.model.TaskListener;
import hudson.model.User;
import hudson.security.ACL;
import hudson.security.ACLContext;
import hudson.slaves.EnvironmentVariablesNodeProperty;
import hudson.tasks.BuildStepMonitor;
import hudson.tasks.Shell;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import jenkins.security.QueueItemAuthenticator;
import jenkins.security.QueueItemAuthenticatorConfiguration;
import jenkins.security.QueueItemAuthenticatorDescriptor;
import org.htmlunit.HttpMethod;
import org.htmlunit.WebRequest;
import org.htmlunit.html.HtmlPage;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.jvnet.hudson.test.TestExtension;
import org.springframework.security.core.Authentication;

import java.io.IOException;
import java.net.URL;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

public class MqttNotifierTest {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    private MqttNotifier createSubject() {
        return new MqttNotifier(
            "tcp://localhost:1883",
            "jenkins/$JOB_NAME",
            "$BUILD_RESULT",
            "1",
            false,
            null
        );
    }

    @Test
    public void canInitiateNewNotifier() {
        MqttNotifier notifier = createSubject();
        assertNotNull(notifier);
    }

    @Test
    public void credentialsLookupRespectsJobScope() throws Exception {
        FreeStyleProject project = j.createFreeStyleProject();
        SystemCredentialsProvider.getInstance().getCredentials().add(
            new UsernamePasswordCredentialsImpl(CredentialsScope.GLOBAL, "global-id", "", "user", "password"));
        SystemCredentialsProvider.getInstance().getCredentials().add(
            new UsernamePasswordCredentialsImpl(CredentialsScope.SYSTEM, "system-id", "", "user", "password"));

        assertNotNull(MqttNotifier.lookupItemCredentials(project, "global-id"));
        assertNull(MqttNotifier.lookupItemCredentials(project, "system-id"));
        assertNull(MqttNotifier.lookupItemCredentials(project, "missing-id"));
        assertNull(MqttNotifier.lookupItemCredentials(null, "global-id"));

        MqttNotifier.DescriptorImpl descriptor = j.jenkins.getDescriptorByType(MqttNotifier.DescriptorImpl.class);
        assertTrue(descriptor.doFillCredentialsIdItems(project, null).stream().anyMatch(option -> "global-id".equals(option.value)));
        assertFalse(descriptor.doFillCredentialsIdItems(project, null).stream().anyMatch(option -> "system-id".equals(option.value)));
        assertTrue(descriptor.doFillCredentialsIdItems(project, "missing-id").stream().anyMatch(option -> "missing-id".equals(option.value)));
        assertEquals(FormValidation.Kind.OK, descriptor.doCheckCredentialsId(project, "").kind);
        assertEquals(FormValidation.Kind.OK, descriptor.doCheckCredentialsId(project, "global-id").kind);
        assertEquals(FormValidation.Kind.ERROR, descriptor.doCheckCredentialsId(project, "system-id").kind);
        assertEquals(FormValidation.Kind.ERROR, descriptor.doCheckCredentialsId(project, "missing-id").kind);
    }

    @Test
    public void credentialsSelectorPreservesMissingIdOnConfigurationRoundTrip() throws Exception {
        FreeStyleProject project = j.createFreeStyleProject();
        MqttNotifier notifier = createSubject();
        notifier.setCredentialsId("missing-id");
        project.getPublishersList().add(notifier);

        HtmlPage config = j.createWebClient().getPage(project, "configure");
        assertEquals(1, config.getByXPath("//div[contains(@class, 'credentials-select-control')]").size());
        assertFalse(config.getByXPath("//*[contains(@class, 'credentials-add-menu')]").isEmpty());
        j.configRoundtrip(project);
        assertEquals("missing-id", project.getPublishersList().get(MqttNotifier.class).getCredentialsId());
    }

    @Test
    public void jobAuthenticationIsUsedForCredentials() throws Exception {
        FreeStyleProject project = j.createFreeStyleProject();
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        User.getById("build-user", true);
        QueueItemAuthenticatorConfiguration.get().getAuthenticators().add(new BuildUserAuthenticator());
        SystemCredentialsProvider.getInstance().getCredentials().add(
            new UsernamePasswordCredentialsImpl(CredentialsScope.GLOBAL, "global-id", "", "user", "password"));

        MqttNotifier.DescriptorImpl descriptor = j.jenkins.getDescriptorByType(MqttNotifier.DescriptorImpl.class);
        assertFalse(descriptor.doFillCredentialsIdItems(project, null).stream().anyMatch(option -> "global-id".equals(option.value)));
        assertNull(MqttNotifier.lookupItemCredentials(project, "global-id"));
        assertEquals(FormValidation.Kind.ERROR, descriptor.doCheckCredentialsId(project, "global-id").kind);
        assertEquals(FormValidation.Kind.ERROR, descriptor.doTestConnection(project, "tcp://localhost:1883", "global-id").kind);

        MqttNotifier notifier = createSubject();
        notifier.setCredentialsId("global-id");
        project.getPublishersList().add(notifier);
        FreeStyleBuild build = j.buildAndAssertSuccess(project);
        j.assertLogContains("MQTT credentials not found or not available to this job", build);
    }

    public static class BuildUserAuthenticator extends QueueItemAuthenticator {
        @Override
        public Authentication authenticate2(Queue.Task task) {
            return User.getById("build-user", false).impersonate2();
        }

        @TestExtension("jobAuthenticationIsUsedForCredentials")
        public static class DescriptorImpl extends QueueItemAuthenticatorDescriptor {
            @Override
            public String getDisplayName() {
                return "Build user";
            }
        }
    }

    @Test
    public void systemCredentialsAreRejectedForBuildAndConnectionTest() throws Exception {
        FreeStyleProject project = j.createFreeStyleProject();
        SystemCredentialsProvider.getInstance().getCredentials().add(
            new UsernamePasswordCredentialsImpl(CredentialsScope.SYSTEM, "system-id", "", "user", "password"));
        MqttNotifier notifier = createSubject();
        notifier.setCredentialsId("system-id");
        project.getPublishersList().add(notifier);

        MqttNotifier.DescriptorImpl descriptor = j.jenkins.getDescriptorByType(MqttNotifier.DescriptorImpl.class);
        assertEquals(FormValidation.Kind.ERROR,
            descriptor.doTestConnection(project, notifier.getBrokerUrl(), "system-id").kind);
        assertEquals(FormValidation.Kind.ERROR,
            descriptor.doTestConnection(null, notifier.getBrokerUrl(), "system-id").kind);

        FreeStyleBuild build = j.buildAndAssertSuccess(project);
        j.assertLogContains("MQTT credentials not found or not available to this job", build);
    }

    @Test
    public void connectionTestRequiresConfigurePermission() throws Exception {
        FreeStyleProject project = j.createFreeStyleProject();
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        j.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy()
            .grant(Jenkins.READ, Item.READ).everywhere().to("reader"));
        MqttNotifier.DescriptorImpl descriptor = j.jenkins.getDescriptorByType(MqttNotifier.DescriptorImpl.class);

        try (ACLContext ignored = ACL.as(User.getById("reader", true))) {
            assertThrows(org.springframework.security.access.AccessDeniedException.class,
                () -> descriptor.doTestConnection(project, "tcp://localhost:1883", "system-id"));
        }
    }

    @Test
    public void connectionTestEndpointRequiresPostAndConfigurePermission() throws Exception {
        FreeStyleProject project = j.createFreeStyleProject();
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        j.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy()
            .grant(Jenkins.READ, Item.READ).everywhere().to("reader")
            .grant(Jenkins.ADMINISTER).everywhere().to("admin"));
        String path = project.getUrl() + "descriptorByName/jenkins.plugins.mqttnotification.MqttNotifier/"
            + "testConnection?brokerUrl=tcp%3A%2F%2Flocalhost%3A1883&credentialsId=missing-id";

        JenkinsRule.WebClient admin = j.createWebClient().login("admin");
        admin.assertFails(path, 405);
        WebRequest adminPost = admin.addCrumb(new WebRequest(new URL(j.getURL(), path), HttpMethod.POST));
        assertEquals(200, admin.getPage(adminPost).getWebResponse().getStatusCode());

        JenkinsRule.WebClient reader = j.createWebClient().login("reader");
        reader.setThrowExceptionOnFailingStatusCode(false);
        WebRequest readerPost = reader.addCrumb(new WebRequest(new URL(j.getURL(), path), HttpMethod.POST));
        assertEquals(403, reader.getPage(readerPost).getWebResponse().getStatusCode());
    }

    @Test
    public void canGetAllFields() {
        MqttNotifier notifier = createSubject();
        assertEquals("jenkins/$JOB_NAME", notifier.getTopic());
        assertEquals("$BUILD_RESULT", notifier.getMessage());
        assertEquals("tcp://localhost:1883", notifier.getBrokerUrl());
        assertEquals("1", notifier.getQos());
        assertEquals(BuildStepMonitor.NONE, notifier.getRequiredMonitorService());
        assertEquals(false, notifier.isNotifyOnStart());
        assertEquals(true, notifier.isNotifyOnComplete());
        assertEquals("jenkins/$JOB_NAME", notifier.getEffectiveStartTopic());
        assertEquals("STARTED", notifier.getEffectiveStartMessage());

        notifier.setNotifyOnStart(true);
        notifier.setNotifyOnComplete(false);
        notifier.setStartTopic("jenkins/start/$JOB_NAME");
        notifier.setStartMessage("Job $JOB_NAME started");

        assertEquals(true, notifier.isNotifyOnStart());
        assertEquals(false, notifier.isNotifyOnComplete());
        assertEquals("jenkins/start/$JOB_NAME", notifier.getStartTopic());
        assertEquals("jenkins/start/$JOB_NAME", notifier.getEffectiveStartTopic());
        assertEquals("Job $JOB_NAME started", notifier.getStartMessage());
        assertEquals("Job $JOB_NAME started", notifier.getEffectiveStartMessage());
    }

    @Test
    public void testReplaceVariablesWithDefaultDisplayName() throws Exception {
        MqttNotifier notifier = createSubject();
        FreeStyleProject project = j.createFreeStyleProject("test-default-name");
        FreeStyleBuild build = project.scheduleBuild2(0).get();

        String template = "{ \"job\": \"${JOB_NAME}\", \"name\": \"${BUILD_DISPLAY_NAME}\", \"state\": \"${BUILD_RESULT}\" }";
        String replaced = notifier.replaceVariables(template, build, TaskListener.NULL);
        System.out.println("Replaced default: " + replaced);
        assertEquals("{ \"job\": \"test-default-name\", \"name\": \"#1\", \"state\": \"SUCCESS\" }", replaced);
    }

    @Test
    public void testReplaceVariablesWithCustomDisplayName() throws Exception {
        MqttNotifier notifier = createSubject();
        FreeStyleProject project = j.createFreeStyleProject("test-custom-name");
        FreeStyleBuild build = project.scheduleBuild2(0).get();
        build.setDisplayName("CustomBuildName-1.0.0");

        String template = "{ \"job\": \"${JOB_NAME}\", \"name\": \"${BUILD_DISPLAY_NAME}\", \"state\": \"${BUILD_RESULT}\" }";
        String replaced = notifier.replaceVariables(template, build, TaskListener.NULL);
        System.out.println("Replaced custom: " + replaced);
        assertEquals("{ \"job\": \"test-custom-name\", \"name\": \"CustomBuildName-1.0.0\", \"state\": \"SUCCESS\" }", replaced);
    }

    @Test
    public void testBuildStartNotificationExecution() throws Exception {
        FreeStyleProject project = j.createFreeStyleProject("test-start-job");
        MqttNotifier notifier = createSubject();
        notifier.setNotifyOnStart(true);
        notifier.setNotifyOnComplete(true);
        notifier.setStartTopic("jenkins/start/$JOB_NAME");
        notifier.setStartMessage("Build #${BUILD_NUMBER} started for ${JOB_NAME}");
        project.getPublishersList().add(notifier);

        FreeStyleBuild build = project.scheduleBuild2(0).get();
        assertEquals(hudson.model.Result.SUCCESS, build.getResult());

        String startTopicReplaced = notifier.replaceVariables(notifier.getEffectiveStartTopic(), build, TaskListener.NULL);
        String startMsgReplaced = notifier.replaceVariables(notifier.getEffectiveStartMessage(), build, TaskListener.NULL);
        assertEquals("jenkins/start/test-start-job", startTopicReplaced);
        assertEquals("Build #1 started for test-start-job", startMsgReplaced);
    }

    public void setEnvironmentVariables() throws IOException {
        EnvironmentVariablesNodeProperty prop = new EnvironmentVariablesNodeProperty();
        EnvVars envVars = prop.getEnvVars();
        envVars.put("sampleEnvVarKey", "sampleEnvVarValue");
        j.jenkins.getGlobalNodeProperties().add(prop);
    }
}

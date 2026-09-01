namespace Legacy.Maliev.DataMigration.Tests;

public sealed class Exact24ShadowRunnerDeploymentContractTests
{
    [Fact]
    public void JobTemplate_UsesImmutableRunnerAndExactInClusterTrustBoundary()
    {
        string template = Read("deploy", "exact24-shadow-runner-job.template.yaml");

        Assert.Equal(2, Count(template, "image: __RUNNER_IMAGE_DIGEST__"));
        Assert.Contains("serviceAccountName: legacy-data-migration-shadow-provisioner", template, StringComparison.Ordinal);
        Assert.Contains("automountServiceAccountToken: false", template, StringComparison.Ordinal);
        Assert.Contains("audience: https://kubernetes.default.svc", template, StringComparison.Ordinal);
        Assert.Contains("expirationSeconds: 600", template, StringComparison.Ordinal);
        Assert.Contains("mountPath: /var/run/secrets/kubernetes.io/serviceaccount", template, StringComparison.Ordinal);
        Assert.Contains("name: kube-root-ca.crt", template, StringComparison.Ordinal);
        Assert.Contains("path: token", template, StringComparison.Ordinal);
        Assert.Contains("path: ca.crt", template, StringComparison.Ordinal);
        Assert.DoesNotContain("kind: Secret", template, StringComparison.Ordinal);
        Assert.DoesNotContain("value: Host=", template, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("value: Server=", template, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void JobTemplate_SeparatesOwnerArtifactsAndSecretReferences()
    {
        string template = Read("deploy", "exact24-shadow-runner-job.template.yaml");

        Assert.Contains("persistentVolumeClaim:", template, StringComparison.Ordinal);
        Assert.Contains("claimName: __RUN_ARTIFACTS_PVC_NAME__", template, StringComparison.Ordinal);
        Assert.Contains("secretName: __SIGNING_SECRET_NAME__", template, StringComparison.Ordinal);
        Assert.Equal(3, Count(template, "name: __RUNTIME_SECRET_NAME__"));
        Assert.Contains("defaultMode: 288", template, StringComparison.Ordinal);
        Assert.Contains("readOnlyRootFilesystem: true", template, StringComparison.Ordinal);
        Assert.Contains("allowPrivilegeEscalation: false", template, StringComparison.Ordinal);
        Assert.Contains("drop: [\"ALL\"]", template, StringComparison.Ordinal);
        Assert.Contains("backoffLimit: 0", template, StringComparison.Ordinal);
        Assert.Contains("LEGACY_DEPLOY_ENABLED", template, StringComparison.Ordinal);
        Assert.Equal(2, Count(template, "value: \"false\""));
    }

    [Fact]
    public void JobTemplate_AuthorizesBeforeExecutingAndPersistsCreateNewOutputs()
    {
        string template = Read("deploy", "exact24-shadow-runner-job.template.yaml");

        int authorize = template.IndexOf("authorize-shadow", StringComparison.Ordinal);
        int execute = template.IndexOf("execute-shadow", StringComparison.Ordinal);
        Assert.True(authorize >= 0 && execute > authorize);
        Assert.Contains("initContainers:", template, StringComparison.Ordinal);
        Assert.Contains("args: [\"authorize-shadow\", \"--config\", \"/run/legacy-migration/run-config.json\"]", template, StringComparison.Ordinal);
        Assert.Contains("args: [\"execute-shadow\", \"--config\", \"/run/legacy-migration/run-config.json\"]", template, StringComparison.Ordinal);
        Assert.Equal(4, Count(template, "mountPath: /run/legacy-migration"));
    }

    [Fact]
    public void JobTemplate_IsolatesAuthorizationAndExecutionPrivateKeys()
    {
        string template = Read("deploy", "exact24-shadow-runner-job.template.yaml");
        string init = Slice(template, "      initContainers:", "      containers:");
        string executor = Slice(template, "      containers:", "      volumes:");

        Assert.Contains("name: authorization-signing-material", init, StringComparison.Ordinal);
        Assert.Contains("authorization-private.pem", init, StringComparison.Ordinal);
        Assert.DoesNotContain("execution-signing-material", init, StringComparison.Ordinal);
        Assert.DoesNotContain("execution-private.pem", init, StringComparison.Ordinal);
        Assert.Contains("name: execution-signing-material", executor, StringComparison.Ordinal);
        Assert.Contains("execution-private.pem", executor, StringComparison.Ordinal);
        Assert.DoesNotContain("authorization-signing-material", executor, StringComparison.Ordinal);
        Assert.DoesNotContain("authorization-private.pem", executor, StringComparison.Ordinal);
        Assert.Equal(2, Count(template, "secretName: __SIGNING_SECRET_NAME__"));
    }

    [Fact]
    public void DockerBuildContract_RequiresCallerSuppliedDigestPinnedBases()
    {
        string dockerfile = Read("deploy", "exact24-shadow-runner.Dockerfile");
        string dockerignore = Read(".dockerignore");
        string builder = Read("scripts", "build-exact24-shadow-runner.ps1");

        Assert.Contains("ARG DOTNET_SDK_IMAGE", dockerfile, StringComparison.Ordinal);
        Assert.Contains("FROM ${DOTNET_SDK_IMAGE} AS build", dockerfile, StringComparison.Ordinal);
        Assert.Contains("ARG DOTNET_RUNTIME_IMAGE", dockerfile, StringComparison.Ordinal);
        Assert.Contains("FROM ${DOTNET_RUNTIME_IMAGE} AS runtime", dockerfile, StringComparison.Ordinal);
        int firstFrom = dockerfile.IndexOf("FROM ", StringComparison.Ordinal);
        Assert.True(dockerfile.IndexOf("ARG DOTNET_SDK_IMAGE", StringComparison.Ordinal) < firstFrom);
        Assert.True(dockerfile.IndexOf("ARG DOTNET_RUNTIME_IMAGE", StringComparison.Ordinal) < firstFrom);
        Assert.DoesNotContain("FROM mcr.microsoft.com/dotnet", dockerfile, StringComparison.Ordinal);
        Assert.Contains("**/bin", dockerignore, StringComparison.Ordinal);
        Assert.Contains("**/obj", dockerignore, StringComparison.Ordinal);
        Assert.Contains("@sha256:[0-9a-f]{64}", builder, StringComparison.Ordinal);
        Assert.Contains("--build-arg \"DOTNET_SDK_IMAGE=$DotNetSdkImage\"", builder, StringComparison.Ordinal);
        Assert.Contains("--build-arg \"DOTNET_RUNTIME_IMAGE=$DotNetRuntimeImage\"", builder, StringComparison.Ordinal);
    }

    [Fact]
    public void CleanupTemplate_IsDormantSecretFreeAndUsesTheSameBoundIdentity()
    {
        string template = Read("deploy", "exact24-shadow-cleanup-job.template.yaml");

        Assert.Contains("args: [\"cleanup-shadows\", \"--config\", \"/run/legacy-migration/run-config.json\"]", template, StringComparison.Ordinal);
        Assert.Contains("args: [\"authorize-cleanup\", \"--config\", \"/run/legacy-migration/run-config.json\"]", template, StringComparison.Ordinal);
        Assert.Contains("serviceAccountName: legacy-data-migration-shadow-provisioner", template, StringComparison.Ordinal);
        Assert.Contains("automountServiceAccountToken: false", template, StringComparison.Ordinal);
        Assert.Contains("audience: https://kubernetes.default.svc", template, StringComparison.Ordinal);
        Assert.Contains("expirationSeconds: 600", template, StringComparison.Ordinal);
        Assert.Contains("claimName: __RUN_ARTIFACTS_PVC_NAME__", template, StringComparison.Ordinal);
        Assert.Equal(2, Count(template, "secretName: __SIGNING_SECRET_NAME__"));
        Assert.Contains("secretName: __SNAPSHOT_SECRET_NAME__", template, StringComparison.Ordinal);
        Assert.Contains("name: __RUNTIME_SECRET_NAME__", template, StringComparison.Ordinal);
        Assert.DoesNotContain("kind: Secret", template, StringComparison.Ordinal);
        Assert.DoesNotContain("value: Host=", template, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("value: Server=", template, StringComparison.OrdinalIgnoreCase);
        string authorizer = Slice(template, "      initContainers:", "      containers:");
        string cleanup = Slice(template, "      containers:", "      volumes:");
        Assert.Contains("authorization-private.pem", authorizer, StringComparison.Ordinal);
        Assert.DoesNotContain("execution-private.pem", authorizer, StringComparison.Ordinal);
        Assert.Contains("execution-private.pem", cleanup, StringComparison.Ordinal);
        Assert.DoesNotContain("authorization-private.pem", cleanup, StringComparison.Ordinal);
    }

    [Fact]
    public void ImageAndJobs_UseFixedNonRootIdentityWithGroupReadableProjections()
    {
        string dockerfile = Read("deploy", "exact24-shadow-runner.Dockerfile");
        string runner = Read("deploy", "exact24-shadow-runner-job.template.yaml");
        string cleanup = Read("deploy", "exact24-shadow-cleanup-job.template.yaml");

        Assert.Contains("USER 65532:65532", dockerfile, StringComparison.Ordinal);
        foreach (string template in new[] { runner, cleanup })
        {
            Assert.Contains("runAsNonRoot: true", template, StringComparison.Ordinal);
            Assert.Contains("runAsUser: 65532", template, StringComparison.Ordinal);
            Assert.Contains("runAsGroup: 65532", template, StringComparison.Ordinal);
            Assert.Contains("fsGroup: 65532", template, StringComparison.Ordinal);
            Assert.Contains("fsGroupChangePolicy: OnRootMismatch", template, StringComparison.Ordinal);
            Assert.Contains("defaultMode: 288", template, StringComparison.Ordinal);
            Assert.Contains("mode: 288", template, StringComparison.Ordinal);
            Assert.DoesNotContain("runAsUser: 0", template, StringComparison.Ordinal);
            Assert.DoesNotContain("runAsGroup: 0", template, StringComparison.Ordinal);
        }
    }

    private static string Read(params string[] path)
    {
        return File.ReadAllText(Path.Combine([FindRepositoryRoot(), .. path]));
    }

    private static int Count(string value, string fragment)
    {
        return (value.Length - value.Replace(fragment, string.Empty, StringComparison.Ordinal).Length) / fragment.Length;
    }

    private static string Slice(string value, string start, string end)
    {
        int startIndex = value.IndexOf(start, StringComparison.Ordinal);
        int endIndex = value.IndexOf(end, startIndex + start.Length, StringComparison.Ordinal);
        Assert.True(startIndex >= 0 && endIndex > startIndex);
        return value[startIndex..endIndex];
    }

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while (current is not null && !File.Exists(Path.Combine(current.FullName, "Legacy.Maliev.DataMigration.slnx")))
        {
            current = current.Parent;
        }

        return current?.FullName ?? throw new DirectoryNotFoundException("Repository root was not found.");
    }
}

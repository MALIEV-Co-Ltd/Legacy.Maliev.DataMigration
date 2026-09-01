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
        Assert.Contains("defaultMode: 256", template, StringComparison.Ordinal);
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
        Assert.Equal(2, Count(template, "mountPath: /run/legacy-migration"));
    }

    [Fact]
    public void DockerBuildContract_RequiresCallerSuppliedDigestPinnedBases()
    {
        string dockerfile = Read("deploy", "exact24-shadow-runner.Dockerfile");
        string builder = Read("scripts", "build-exact24-shadow-runner.ps1");

        Assert.Contains("ARG DOTNET_SDK_IMAGE", dockerfile, StringComparison.Ordinal);
        Assert.Contains("FROM ${DOTNET_SDK_IMAGE} AS build", dockerfile, StringComparison.Ordinal);
        Assert.Contains("ARG DOTNET_RUNTIME_IMAGE", dockerfile, StringComparison.Ordinal);
        Assert.Contains("FROM ${DOTNET_RUNTIME_IMAGE} AS runtime", dockerfile, StringComparison.Ordinal);
        Assert.DoesNotContain("FROM mcr.microsoft.com/dotnet", dockerfile, StringComparison.Ordinal);
        Assert.Contains("@sha256:[0-9a-f]{64}", builder, StringComparison.Ordinal);
        Assert.Contains("--build-arg \"DOTNET_SDK_IMAGE=$DotNetSdkImage\"", builder, StringComparison.Ordinal);
        Assert.Contains("--build-arg \"DOTNET_RUNTIME_IMAGE=$DotNetRuntimeImage\"", builder, StringComparison.Ordinal);
    }

    private static string Read(params string[] path)
    {
        return File.ReadAllText(Path.Combine([FindRepositoryRoot(), .. path]));
    }

    private static int Count(string value, string fragment)
    {
        return (value.Length - value.Replace(fragment, string.Empty, StringComparison.Ordinal).Length) / fragment.Length;
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

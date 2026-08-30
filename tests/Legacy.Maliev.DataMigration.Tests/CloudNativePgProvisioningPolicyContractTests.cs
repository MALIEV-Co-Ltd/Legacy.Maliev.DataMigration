namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CloudNativePgProvisioningPolicyContractTests
{
    [Fact]
    public void DormantPolicy_BindsDedicatedIdentityAndExactRunOwnedBoundary()
    {
        string root = FindRepositoryRoot();
        string policy = File.ReadAllText(Path.Combine(root, "deploy", "cloudnativepg-shadow-provisioner-policy.yaml"));

        Assert.Contains("system:serviceaccount:maliev-legacy:legacy-data-migration-shadow-provisioner", policy, StringComparison.Ordinal);
        Assert.Contains("verbs: [\"get\", \"create\", \"patch\", \"delete\"]", policy, StringComparison.Ordinal);
        Assert.DoesNotContain("\"list\"", policy, StringComparison.Ordinal);
        Assert.DoesNotContain("\"watch\"", policy, StringComparison.Ordinal);
        Assert.Contains("legacy-postgres-main", policy, StringComparison.Ordinal);
        Assert.Contains("legacy_migration_shadow", policy, StringComparison.Ordinal);
        Assert.Contains("owner-run-id", policy, StringComparison.Ordinal);
        Assert.Contains("owner-attempt", policy, StringComparison.Ordinal);
        Assert.Contains("fencing-token", policy, StringComparison.Ordinal);
        Assert.Contains("failurePolicy: Fail", policy, StringComparison.Ordinal);
        Assert.Contains("validationActions: [Deny]", policy, StringComparison.Ordinal);
    }

    [Fact]
    public void DormantPolicy_FailsClosedForEveryShadowMutationAndPreservesCanonicalResources()
    {
        string policy = ReadPolicy();

        Assert.Contains("name: shadow-resources-only", policy, StringComparison.Ordinal);
        Assert.Contains("request.namespace == 'maliev-legacy'", policy, StringComparison.Ordinal);
        Assert.Contains("object.metadata.name.matches('^legacy-shadow-", policy, StringComparison.Ordinal);
        Assert.Contains("oldObject.metadata.name.matches('^legacy-shadow-", policy, StringComparison.Ordinal);
        Assert.Contains("request.userInfo.username == 'system:serviceaccount:maliev-legacy:legacy-data-migration-shadow-provisioner'", policy, StringComparison.Ordinal);
        Assert.Contains("Only the dedicated migration identity may mutate legacy shadow resources.", policy, StringComparison.Ordinal);

        int matchStart = policy.IndexOf("matchConditions:", StringComparison.Ordinal);
        int validationStart = policy.IndexOf("validations:", matchStart, StringComparison.Ordinal);
        string matchConditions = policy[matchStart..validationStart];
        Assert.DoesNotContain("request.userInfo", matchConditions, StringComparison.Ordinal);
    }

    [Fact]
    public void DormantPolicy_EnforcesOperationSpecificReclaimIdentityAndDeleteFence()
    {
        string policy = ReadPolicy();

        Assert.Contains("request.operation != 'CREATE' || object.spec.databaseReclaimPolicy == 'delete'", policy, StringComparison.Ordinal);
        Assert.Contains("request.operation != 'UPDATE' || (object.spec.databaseReclaimPolicy == 'delete' && oldObject.spec.databaseReclaimPolicy == 'delete' && oldObject.spec.name == object.spec.name)", policy, StringComparison.Ordinal);
        Assert.Contains("request.operation != 'DELETE' || (oldObject.spec.databaseReclaimPolicy == 'delete' && oldObject.spec.allowConnections == false && oldObject.spec.ensure == 'absent')", policy, StringComparison.Ordinal);
        Assert.Contains("Shadow PostgreSQL names are immutable during updates.", policy, StringComparison.Ordinal);
        Assert.Contains("Shadow deletion requires the fenced disabled absent state and delete reclaim policy.", policy, StringComparison.Ordinal);
    }

    private static string ReadPolicy()
    {
        string root = FindRepositoryRoot();
        return File.ReadAllText(Path.Combine(root, "deploy", "cloudnativepg-shadow-provisioner-policy.yaml"));
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Legacy.Maliev.DataMigration.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new InvalidOperationException("Repository root not found.");
    }
}

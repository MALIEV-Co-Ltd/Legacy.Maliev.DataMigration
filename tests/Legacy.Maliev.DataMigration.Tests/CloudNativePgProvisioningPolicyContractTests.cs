namespace Legacy.Maliev.DataMigration.Tests;

public sealed partial class CloudNativePgProvisioningPolicyContractTests
{
    [Fact]
    public void DormantPolicy_BindsDedicatedIdentityAndExactRunOwnedBoundary()
    {
        string root = FindRepositoryRoot();
        string policy = File.ReadAllText(Path.Combine(root, "deploy", "cloudnativepg-shadow-provisioner-policy.yaml"));

        Assert.Contains("system:serviceaccount:maliev-legacy:legacy-data-migration-shadow-provisioner", policy, StringComparison.Ordinal);
        Assert.Contains("verbs: [\"get\", \"create\", \"patch\", \"delete\"]", policy, StringComparison.Ordinal);
        Assert.Contains("resources: [\"clusters\"]", policy, StringComparison.Ordinal);
        Assert.Contains("resourceNames: [\"legacy-postgres-main\"]", policy, StringComparison.Ordinal);
        Assert.Contains("verbs: [\"get\"]", policy, StringComparison.Ordinal);
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

        Assert.DoesNotContain("matchConditions:", policy, StringComparison.Ordinal);
        Assert.Contains("request.namespace == 'maliev-legacy'", policy, StringComparison.Ordinal);
        Assert.Contains("(object == null ? oldObject : object).metadata.name.matches('^legacy-shadow-", policy, StringComparison.Ordinal);
        Assert.Contains("(object == null ? oldObject : object).spec.name.matches('^legacy_shadow_", policy, StringComparison.Ordinal);
        Assert.Contains("request.userInfo.username == 'system:serviceaccount:maliev-legacy:legacy-data-migration-shadow-provisioner'", policy, StringComparison.Ordinal);
        Assert.Contains("Only the dedicated migration identity may mutate legacy shadow resources.", policy, StringComparison.Ordinal);

        Assert.Contains("Only exact run-owned shadow Database resources are permitted.", policy, StringComparison.Ordinal);
    }

    [Fact]
    public void DormantPolicy_AllowsOnlyDedicatedIdentityAndWellFormedRunOwnedShadowMutations()
    {
        const string shadowMetadata = "legacy-shadow-order-0123456789abcdef0123456789abcdef";
        const string shadowDatabase = "legacy_shadow_order_0123456789abcdef0123456789abcdef";
        const string identity = "system:serviceaccount:maliev-legacy:legacy-data-migration-shadow-provisioner";

        Assert.True(AdmissionAllows("maliev-legacy", identity, shadowMetadata, shadowDatabase));
        Assert.False(AdmissionAllows("maliev-legacy", identity, "legacy-postgres-order", "Order"));
        Assert.False(AdmissionAllows("maliev-legacy", identity, "legacy-shadow-order", "legacy_shadow_order"));
        Assert.False(AdmissionAllows("maliev-legacy", "system:serviceaccount:maliev-legacy:default", shadowMetadata, shadowDatabase));
        Assert.False(AdmissionAllows("default", identity, shadowMetadata, shadowDatabase));
    }

    [Theory]
    [InlineData("CREATE")]
    [InlineData("UPDATE")]
    [InlineData("DELETE")]
    public void DormantPolicy_ExplicitlyDeniesCanonicalAndMalformedResourcesForEveryMutation(string operation)
    {
        string policy = ReadPolicy();
        Assert.Contains("operations: [\"CREATE\", \"UPDATE\", \"DELETE\"]", policy, StringComparison.Ordinal);
        Assert.False(AdmissionAllows("maliev-legacy",
            "system:serviceaccount:maliev-legacy:legacy-data-migration-shadow-provisioner",
            operation == "DELETE" ? null : "legacy-postgres-order",
            operation == "DELETE" ? null : "Order",
            operation == "CREATE" ? null : "legacy-postgres-order",
            operation == "CREATE" ? null : "Order"));
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

    private static bool AdmissionAllows(
        string namespaceName,
        string identity,
        string? currentMetadataName,
        string? currentDatabaseName,
        string? oldMetadataName = null,
        string? oldDatabaseName = null)
    {
        string? metadata = currentMetadataName ?? oldMetadataName;
        string? database = currentDatabaseName ?? oldDatabaseName;
        return namespaceName == "maliev-legacy" &&
            identity == "system:serviceaccount:maliev-legacy:legacy-data-migration-shadow-provisioner" &&
            IsShadowMetadata(metadata) && IsShadowDatabase(database);
    }

    private static bool IsShadowMetadata(string? value)
    {
        return value is not null && ShadowMetadataRegex().IsMatch(value);
    }

    private static bool IsShadowDatabase(string? value)
    {
        return value is not null && value.Length <= 63 && ShadowDatabaseRegex().IsMatch(value);
    }

    [System.Text.RegularExpressions.GeneratedRegex(
        "^legacy-shadow-[a-z0-9-]+-[0-9a-f]{32}$",
        System.Text.RegularExpressions.RegexOptions.CultureInvariant)]
    private static partial System.Text.RegularExpressions.Regex ShadowMetadataRegex();

    [System.Text.RegularExpressions.GeneratedRegex(
        "^legacy_shadow_[a-z0-9_]+_[0-9a-f]{32}$",
        System.Text.RegularExpressions.RegexOptions.CultureInvariant)]
    private static partial System.Text.RegularExpressions.Regex ShadowDatabaseRegex();

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

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
    public void DormantPolicy_SelectsMigrationIdentityOrShadowObjectsAndPreservesUnrelatedCanonicalResources()
    {
        string policy = ReadPolicy();

        Assert.Contains("matchConditions:", policy, StringComparison.Ordinal);
        Assert.Contains("name: migration-identity-or-shadow-object", policy, StringComparison.Ordinal);
        Assert.Contains("request.userInfo.username == 'system:serviceaccount:maliev-legacy:legacy-data-migration-shadow-provisioner' || (object != null && object.metadata.name.startsWith('legacy-shadow-')) || (oldObject != null && oldObject.metadata.name.startsWith('legacy-shadow-'))", policy, StringComparison.Ordinal);
        Assert.Contains("request.namespace == 'maliev-legacy'", policy, StringComparison.Ordinal);
        Assert.Contains("(object == null ? oldObject : object).metadata.name.matches('^legacy-shadow-", policy, StringComparison.Ordinal);
        Assert.Contains("(object == null ? oldObject : object).spec.name.matches('^legacy_shadow_", policy, StringComparison.Ordinal);
        Assert.Contains("request.userInfo.username == 'system:serviceaccount:maliev-legacy:legacy-data-migration-shadow-provisioner'", policy, StringComparison.Ordinal);
        Assert.Contains("Only the dedicated migration identity may mutate legacy shadow resources.", policy, StringComparison.Ordinal);

        Assert.Contains("Only exact run-owned shadow Database resources are permitted.", policy, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("CREATE")]
    [InlineData("UPDATE")]
    [InlineData("DELETE")]
    public void DormantPolicy_AdmissionSelectionAndValidationMatchRequiredSemanticMatrix(string operation)
    {
        const string shadowMetadata = "legacy-shadow-order-0123456789abcdef0123456789abcdef";
        const string shadowDatabase = "legacy_shadow_order_0123456789abcdef0123456789abcdef";
        const string migrationIdentity = "system:serviceaccount:maliev-legacy:legacy-data-migration-shadow-provisioner";
        const string otherIdentity = "system:serviceaccount:maliev-legacy:cloudnative-pg";

        Assert.Contains("operations: [\"CREATE\", \"UPDATE\", \"DELETE\"]", ReadPolicy(), StringComparison.Ordinal);
        AssertDecision(operation, migrationIdentity, shadowMetadata, shadowDatabase, selected: true, allowed: true);
        AssertDecision(operation, migrationIdentity, "legacy-postgres-order", "Order", selected: true, allowed: false);
        AssertDecision(operation, otherIdentity, shadowMetadata, shadowDatabase, selected: true, allowed: false);
        AssertDecision(operation, otherIdentity, "legacy-postgres-order", "Order", selected: false, allowed: false);
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

    private static void AssertDecision(
        string operation,
        string identity,
        string metadataName,
        string databaseName,
        bool selected,
        bool allowed)
    {
        string? currentMetadata = operation == "DELETE" ? null : metadataName;
        string? currentDatabase = operation == "DELETE" ? null : databaseName;
        string? oldMetadata = operation == "CREATE" ? null : metadataName;
        string? oldDatabase = operation == "CREATE" ? null : databaseName;

        Assert.Equal(selected, AdmissionSelected(identity, currentMetadata, oldMetadata));
        Assert.Equal(allowed, AdmissionAllows(
            "maliev-legacy",
            identity,
            currentMetadata,
            currentDatabase,
            oldMetadata,
            oldDatabase));
    }

    private static bool AdmissionSelected(
        string identity,
        string? currentMetadataName,
        string? oldMetadataName)
    {
        return identity == "system:serviceaccount:maliev-legacy:legacy-data-migration-shadow-provisioner" ||
            IsShadowCandidate(currentMetadataName) || IsShadowCandidate(oldMetadataName);
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
        return AdmissionSelected(identity, currentMetadataName, oldMetadataName) &&
            namespaceName == "maliev-legacy" &&
            identity == "system:serviceaccount:maliev-legacy:legacy-data-migration-shadow-provisioner" &&
            IsShadowMetadata(metadata) && IsShadowDatabase(database);
    }

    private static bool IsShadowCandidate(string? value)
    {
        return value?.StartsWith("legacy-shadow-", StringComparison.Ordinal) == true;
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

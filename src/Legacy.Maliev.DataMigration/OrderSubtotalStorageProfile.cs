using System.Reflection;
using System.Runtime.Loader;

namespace Legacy.Maliev.DataMigration;

// Not a serializable proof or permit. Only the fixed accepted Console rehearsal can issue this storage operand.
internal sealed class OrderSubtotalStorageProfile
{
    private const string IssuerName = "Legacy.Maliev.DataMigration.Console.OrderSubtotalRuntime+Rehearsal";
    private readonly OrderSubtotalCharacterization _facts;
    private OrderSubtotalStorageProfile(OrderSubtotalCharacterization facts) { _facts = OrderSubtotalRepairProtocol.Copy(facts); }
    internal static async Task<OrderSubtotalStorageProfile> AuthenticateAsync(object issuer, string contractSha256,
        string targetBeforeSha256, string sourceSha256, string runnerSha256, CancellationToken ct)
    {
        Type type = issuer.GetType();
        if (!type.IsSealed || type.FullName != IssuerName || type.Assembly.GetName().Name != "Legacy.Maliev.DataMigration.Console" ||
            AssemblyLoadContext.GetLoadContext(type.Assembly) != AssemblyLoadContext.Default || type.GetConstructors(BindingFlags.Public | BindingFlags.Instance).Length != 0)
        { throw OrderSubtotalRepairProtocol.Invalid(); }
        RequireCodeOrigin(type.Assembly); RequireCodeOrigin(typeof(OrderSubtotalStorageProfile).Assembly);
        var method = type.GetMethod("GetCharacterizationAsync", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.DeclaredOnly,
            null, [typeof(CancellationToken)], null) ?? throw OrderSubtotalRepairProtocol.Invalid();
        if (method.ReturnType != typeof(Task<OrderSubtotalCharacterization>)) { throw OrderSubtotalRepairProtocol.Invalid(); }
        var facts = await ((Task<OrderSubtotalCharacterization>?)method.Invoke(issuer, [ct]) ?? throw OrderSubtotalRepairProtocol.Invalid()).ConfigureAwait(false);
        OrderSubtotalRepairProtocol.RequireCharacterization(facts, contractSha256, targetBeforeSha256, sourceSha256, runnerSha256, DateTimeOffset.UtcNow);
        return new(facts);
    }
    internal void RequireBound(OrderSubtotalExpressionRepairNativeObservation before, OrderSubtotalExpressionRepairContract contract)
    {
        OrderSubtotalRepairProtocol.RequireCharacterization(_facts, contract.ComputeSha256(), OrderSubtotalRepairProtocol.NativeSha(before),
            contract.LogicalSourcePlanSha256, _facts.RunnerSha256, DateTimeOffset.UtcNow);
    }
    internal void RequireStorage(string role, long before, long after, int provider, bool alphabetical)
    {
        if (DateTimeOffset.UtcNow >= _facts.ExpiresAtUtc || provider != _facts.ProviderVersion || alphabetical != _facts.Alphabetical ||
            !_facts.Storage.TryGetValue(role, out var expected) || expected.BeforeBlocks != before || expected.AfterBlocks != after)
        { throw OrderSubtotalRepairProtocol.Invalid(); }
    }
    internal void RequireLive()
    { if (DateTimeOffset.UtcNow >= _facts.ExpiresAtUtc) { throw OrderSubtotalRepairProtocol.Invalid(); } }
    private static void RequireCodeOrigin(Assembly assembly)
    {
        const string root = @"B:\maliev-legacy\Legacy.Maliev.DataMigration\src\Legacy.Maliev.DataMigration.Console\bin\Release\net10.0";
        if (assembly.GetName().Name is not ("Legacy.Maliev.DataMigration" or "Legacy.Maliev.DataMigration.Console") ||
            AssemblyLoadContext.GetLoadContext(assembly) != AssemblyLoadContext.Default || assembly.IsDynamic) { throw OrderSubtotalRepairProtocol.Invalid(); }
        string expected = Path.Combine(root, assembly.GetName().Name + ".dll");
        SecureLocalFile.EnsureOwnerOnlyDirectory(root);
        using var actual = SecureLocalFile.OpenReadShared(assembly.Location); using var accepted = SecureLocalFile.OpenReadShared(expected);
        if (!SecureLocalFile.HandleResolvesToApprovedPath(actual, assembly.Location) || !SecureLocalFile.HandleResolvesToApprovedPath(accepted, expected) ||
            !System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(System.Security.Cryptography.SHA256.HashData(actual), System.Security.Cryptography.SHA256.HashData(accepted)))
        { throw OrderSubtotalRepairProtocol.Invalid(); }
    }
}

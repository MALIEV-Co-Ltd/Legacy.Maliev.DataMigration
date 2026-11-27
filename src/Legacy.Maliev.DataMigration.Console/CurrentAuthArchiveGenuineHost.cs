using System.Reflection;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthArchiveGenuineHostConfiguration(string Kind, string Phase, string CaseId,
    CurrentAuthArchiveComponentReadbackInput Inputs, string FirstFixtureParent, string SecondFixtureParent);

internal sealed record CurrentAuthArchiveGenuineChildConfiguration(string Kind, string Root, string RunBindingSha256,
    string GatePath, string GateNonce, DateTimeOffset ExpiresAtUtc, CurrentAuthArchiveGenuineHostConfiguration Request);

/// <summary>Archive-specific trusted-input prerequisite. No owned-pair producer, permit, execution or proof publication.</summary>
internal static class CurrentAuthArchiveGenuineHost
{
    internal const string ProviderCommand = "provider-current-auth-archive-proof";
    internal const string ChildCommand = "run-current-auth-archive-genuine-testhost";
    internal const string ProviderKind = "current-auth-archive-genuine-host-request-v1";
    internal const string ChildKind = "current-auth-archive-genuine-child-request-v1";
    private const string CaseType = "Legacy.Maliev.DataMigration.Tests.CurrentAuthArchiveGuardedExecutionTests";
    private const string ReaderType = "Legacy.Maliev.DataMigration.Tests.CurrentAuthArchiveGenuineInputReader";

    internal static void RequireInput(CurrentAuthArchiveGenuineHostConfiguration request)
    {
        if (request is null || request.Kind != ProviderKind || request.Inputs is null) { throw Invalid("configuration_family"); }
        _ = CurrentAuthArchiveGenuineCases.Require(request.Phase, request.CaseId);
        CurrentAuthArchiveInitialProducer.RequireInput(new(request.Inputs, request.FirstFixtureParent, request.SecondFixtureParent));
        if (Path.GetFileName(request.Inputs.TestImage.Path) != "Legacy.Maliev.DataMigration.Tests.dll")
        { throw Invalid("test_image"); }
    }

    internal static void RequireChildInput(CurrentAuthArchiveGenuineChildConfiguration child, DateTimeOffset now)
    {
        if (child is null || child.Kind != ChildKind || child.Request is null) { throw Invalid("configuration_family"); }
        RequireInput(child.Request);
        if (string.IsNullOrWhiteSpace(child.Root) || !Path.IsPathFullyQualified(child.Root) ||
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(child.Root)) != child.Root ||
            !StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(child.Request.Inputs.ParentBinding.Path), child.Root) ||
            child.RunBindingSha256 != child.Request.Inputs.ParentBinding.Sha256 ||
            !Guid.TryParseExact(child.GateNonce, "N", out _) ||
            child.GatePath != Path.Combine(child.Root, "auth-archive-genuine-gate-" + child.GateNonce + ".json") ||
            now.Offset != TimeSpan.Zero || child.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            child.ExpiresAtUtc <= now || child.ExpiresAtUtc > now.AddMinutes(8))
        { throw Invalid("child_binding"); }
    }

    internal static void RequireCompleteCaseInventory(Assembly tests)
    {
        if (tests.GetName().Name != "Legacy.Maliev.DataMigration.Tests") { throw Invalid("case_assembly"); }
        Type? type = tests.GetType(CaseType, throwOnError: false);
        if (type is null || !type.IsSealed) { throw Invalid("cases_missing"); }
        string[] expected = [.. CurrentAuthArchiveGenuineCases.Inventory().Select(x => x.MethodName).Order(StringComparer.Ordinal)];
        MethodInfo[] methods = [.. type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Where(x => x.Name.StartsWith("Archive_", StringComparison.Ordinal))];
        if (!methods.Select(x => x.Name).Order(StringComparer.Ordinal).SequenceEqual(expected, StringComparer.Ordinal) ||
            methods.Any(method => method.ReturnType != typeof(Task) || method.GetParameters().Length != 0 ||
                !HasFixedCaseAttribute(method, CurrentAuthArchiveGenuineCases.Inventory().Single(item => item.MethodName == method.Name))))
        { throw Invalid("cases_missing"); }
    }

    private static bool HasFixedCaseAttribute(MethodInfo method, CurrentAuthArchiveGenuineCase item)
    {
        string name = (item.Phase, item.CaseId) switch
        {
            ("helper", "dual-durable-readback") => "CurrentAuthArchiveGenuineDualHelperFactAttribute",
            ("helper", _) => "CurrentAuthArchiveGenuineRecoveryHelperFactAttribute",
            ("recovery", _) => "CurrentAuthArchiveRecoveryV2FactAttribute",
            ("native", "host-unprobed-sdk" or "local-trust") => "CurrentAuthArchiveGenuinePreflightFactAttribute",
            ("native" or "delete", _) => "CurrentAuthArchiveGenuineExecutionFactAttribute",
            _ => throw Invalid("cases_missing"),
        };
        CustomAttributeData[] attributes = [.. method.CustomAttributes.Where(attribute =>
            attribute.AttributeType.FullName == "Legacy.Maliev.DataMigration.Tests." + name)];
        if (attributes.Length != 1) { return false; }
        var attribute = attributes[0];
        return attribute.AttributeType.Assembly == method.DeclaringType!.Assembly && attribute.AttributeType.IsSealed &&
            (attribute.AttributeType.BaseType?.FullName) == "Xunit.FactAttribute" && attribute.NamedArguments.Count == 0 && (name == "CurrentAuthArchiveGenuineDualHelperFactAttribute"
            ? attribute.ConstructorArguments.Count == 0
            : attribute.ConstructorArguments.Count == 1 && attribute.ConstructorArguments[0].Value is string id && id == item.CaseId);
    }
    internal static async Task AuthenticateAsync(CurrentAuthArchiveGenuineHostConfiguration request, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        RequireInput(request);
        CurrentAuthArchiveCapacity.Require(admission: true);
        _ = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false);
        string root = Path.GetDirectoryName(request.Inputs.TestImage.Path) ?? throw Invalid("test_image");
        using var held = await CurrentAuthTypedHostProducer.HoldFixedTestBundleAsync(root, ct).ConfigureAwait(false);
        using var context = new CurrentAuthArchiveInitialProducer.FixedNativeBundle(request.Inputs.TestImage.Path);
        try
        {
            Assembly tests = context.LoadFromAssemblyPath(request.Inputs.TestImage.Path);
            MethodInfo reader = tests.GetType(ReaderType, throwOnError: true)!.GetMethod("AuthenticateAsync",
                BindingFlags.Static | BindingFlags.NonPublic, binder: null,
                types: [typeof(CurrentAuthArchiveGenuineHostConfiguration), typeof(CancellationToken)], modifiers: null)
                ?? throw Invalid("input_reader");
            held.Require();
            var pending = reader.Invoke(null, [request, ct]) as Task ?? throw Invalid("input_reader");
            await pending.ConfigureAwait(false);
            held.Require();
        }
        finally { context.Unload(); }
    }

    internal static async Task AuthenticateChildAsync(CurrentAuthArchiveGenuineChildConfiguration child, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        RequireChildInput(child, DateTimeOffset.UtcNow);
        using var lease = CancellationTokenSource.CreateLinkedTokenSource(ct);
        lease.CancelAfter(child.ExpiresAtUtc - DateTimeOffset.UtcNow);
        // A parent gate proves job membership only. The child independently opens the
        // qualified bundle, held source/precursor, signatures, owner and custody inputs.
        await AuthenticateAsync(child.Request, lease.Token).ConfigureAwait(false);
        RequireChildInput(child, DateTimeOffset.UtcNow);
    }

    // No marker, reflection-discovered type or caller callback can turn this prerequisite into a producer.
    internal static void RequireOwnedPairProducer()
    {
        throw Invalid("owned_pair_producer_unavailable");
    }

    internal static MigrationExecutionException Invalid(string facet)
    {
        return new("current_auth_archive_genuine_" + facet,
        "The archive host prerequisite is incomplete or outside its fixed authenticated input contract.");
    }
}

public static partial class MigrationConsole
{
    private static async Task<int> RunCurrentAuthArchiveGenuineHostAsync(string configPath, TextWriter output, TextWriter error, CancellationToken ct)
    {
        _ = output;
        using var lease = CancellationTokenSource.CreateLinkedTokenSource(ct);
        lease.CancelAfter(TimeSpan.FromMinutes(8));
        try
        {
            var request = await ReadProtectedJsonAsync<CurrentAuthArchiveGenuineHostConfiguration>(configPath,
                "current_auth_archive_genuine_config_unprotected", lease.Token).ConfigureAwait(false);
            await CurrentAuthArchiveGenuineHost.AuthenticateAsync(request, lease.Token).ConfigureAwait(false);
            CurrentAuthArchiveGenuineHost.RequireOwnedPairProducer();
        }
        catch (Exception failure) when (failure is MigrationExecutionException or IOException or UnauthorizedAccessException or
            JsonException or ArgumentException or InvalidOperationException or TargetInvocationException or OperationCanceledException)
        {
            await error.WriteLineAsync("current_auth_archive_genuine_prerequisite_refused_no_proof").ConfigureAwait(false);
            return 1;
        }
        // The prerequisite deliberately has no successful provider return or completion artifact.
        return 1;
    }
}

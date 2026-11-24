using System.Reflection;
using System.Runtime.Loader;
using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration;

// Unactivated prerequisite only. No permit or persistent entrypoint calls this.
internal sealed partial class CurrentAuthArchiveGenuineCapability
{
    private const string IssuerType = "Legacy.Maliev.DataMigration.Console.CurrentAuthArchiveGenuineIssuer";
    private const string EnvironmentType = "Legacy.Maliev.DataMigration.Console.CurrentAuthLocalSessionArchiveEnvironment";
    private const string AcceptedBundle = @"B:\maliev-legacy\Legacy.Maliev.DataMigration\tests\Legacy.Maliev.DataMigration.Tests\bin\Release\net10.0";
    private readonly object _issuer;
    private readonly MethodInfo _require, _reserve;
    private readonly Guid _capabilityId;
    private readonly CurrentAuthArchiveGenuineAttestation _binding;
    private readonly string _factsSha256;
    private int _state; // fresh0, reserved1, stopped2; never reusable.

    private CurrentAuthArchiveGenuineCapability(object issuer, MethodInfo require, MethodInfo reserve, Guid capabilityId,
        CurrentAuthArchiveGenuineAttestation binding)
    {
        _issuer = issuer; _require = require; _reserve = reserve; _capabilityId = capabilityId; _binding = binding; _factsSha256 = Facts(binding);
    }

    internal static async Task<CurrentAuthArchiveGenuineCapability> AuthenticateConsoleOwnedIssuerAsync(object issuer, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(issuer);
        Type type = issuer.GetType();
        if (!type.IsSealed || type.FullName != IssuerType || type.Assembly.GetName().Name != "Legacy.Maliev.DataMigration.Console" ||
            AssemblyLoadContext.GetLoadContext(type.Assembly) != AssemblyLoadContext.Default ||
            type.GetConstructors(BindingFlags.Instance | BindingFlags.Public).Length != 0) { throw Invalid(); }
        // No method on a merely same-named object is invoked before its actual
        // loaded code is compared with the owner-protected accepted bundle.
        RequireAcceptedCodeOrigin(type.Assembly);
        RequireAcceptedCodeOrigin(typeof(CurrentAuthArchiveGenuineCapability).Assembly);
        // Three fixed typed entries. No caller-selected member, factory or callback.
        MethodInfo mint = FixedMethod(type, "MintOwnedCapabilityAsync", typeof(Task<CurrentAuthArchiveGenuineAttestation>), [typeof(Guid), typeof(CancellationToken)]);
        MethodInfo require = FixedMethod(type, "RequireOwnedCapabilityAsync", typeof(Task<CurrentAuthArchiveGenuineAttestation>), [typeof(Guid), typeof(bool), typeof(CancellationToken)]);
        MethodInfo reserve = FixedMethod(type, "ReserveOwnedCapabilityAsync", typeof(Task), [typeof(Guid), typeof(CancellationToken)]);
        Guid capabilityId = Guid.NewGuid();
        var pending = mint.Invoke(issuer, [capabilityId, ct]) as Task<CurrentAuthArchiveGenuineAttestation> ?? throw Invalid();
        CurrentAuthArchiveGenuineAttestation binding = await pending.ConfigureAwait(false);
        RequireBinding(issuer, binding);
        return new(issuer, require, reserve, capabilityId, binding);
    }

    internal async Task RequireAsync(CancellationToken ct)
    {
        if (Volatile.Read(ref _state) == 2) { throw Invalid(); }
        try
        {
            var actual = await InvokeAsync(_issuer, _require, _capabilityId, Volatile.Read(ref _state) == 0, ct);
            RequireBinding(_issuer, actual);
            if (!ReferenceEquals(actual.Environment, _binding.Environment) || !ReferenceEquals(actual.Trust, _binding.Trust) || Facts(actual) != _factsSha256 ||
                Volatile.Read(ref _state) == 2) { throw Invalid(); }
        }
        catch { Stop(); throw; }
    }

    internal async Task ReserveOnceAsync(CancellationToken ct)
    {
        await RequireAsync(ct);
        if (Interlocked.CompareExchange(ref _state, 1, 0) != 0) { throw Invalid(); }
        try
        {
            var pending = _reserve.Invoke(_issuer, [_capabilityId, ct]) as Task ?? throw Invalid();
            await pending.ConfigureAwait(false);
            await RequireAsync(ct);
        }
        catch { Stop(); throw; }
    }

    internal void Stop()
    {
        _ = Interlocked.Exchange(ref _state, 2);
    }

    private static MethodInfo FixedMethod(Type type, string name, Type result, Type[] parameters)
    {
        MethodInfo method = type.GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.DeclaredOnly,
            binder: null, types: parameters, modifiers: null) ?? throw Invalid();
        return method.ReturnType == result ? method : throw Invalid();
    }

    private static async Task<CurrentAuthArchiveGenuineAttestation> InvokeAsync(object issuer, MethodInfo method, Guid capabilityId, bool baseline, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var pending = method.Invoke(issuer, [capabilityId, baseline, ct]) as Task<CurrentAuthArchiveGenuineAttestation> ?? throw Invalid();
        return await pending.ConfigureAwait(false);
    }

    private static void RequireBinding(object issuer, CurrentAuthArchiveGenuineAttestation binding)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        if (binding is null || binding.Scope is null || binding.Subject is null || binding.Source is null || binding.Environment is null ||
            binding.Phase != "helper" || CurrentAuthArchiveGenuineRecoveryHelpers.CaseId(CurrentAuthArchiveGenuineRecoveryHelpers.Parse(binding.CaseId)) != binding.Subject.Seed.CaseId ||
            binding.Subject != binding.Scope.ComponentSubject) { throw Invalid(); }
        CurrentAuthArchiveComponentBootstrap.RequireClaims(binding.Scope, binding.Trust, binding.Pins, now);
        var seed = binding.Subject.Seed;
        RequireImage(issuer.GetType().Assembly, binding.ConsoleImagePath, seed.ConsoleAssemblySha256);
        RequireImage(typeof(CurrentAuthArchiveGenuineCapability).Assembly, binding.CoreImagePath, seed.CoreAssemblySha256);
        Assembly[] tests = AppDomain.CurrentDomain.GetAssemblies().Where(x => x.GetName().Name == "Legacy.Maliev.DataMigration.Tests").ToArray();
        if (tests.Length != 1) { throw Invalid(); }
        RequireImage(tests[0], binding.TestImagePath, seed.TestAssemblySha256);
        Type environment = binding.Environment.GetType();
        if (!environment.IsSealed || environment.FullName != EnvironmentType || environment.Assembly != issuer.GetType().Assembly ||
            binding.Source.SourceCommitSha != seed.AcceptedSourceCommitSha || SchemaPlanCanonicalizer.ComputeSha256(binding.Source) != seed.SourceSchemaPlanSha256 ||
            binding.Source.CapturedAtUtc.Offset != TimeSpan.Zero || binding.Source.CapturedAtUtc > now || now - binding.Source.CapturedAtUtc > TimeSpan.FromMinutes(5))
        { throw Invalid(); }
    }

    private static void RequireImage(Assembly assembly, string path, string expected)
    {
        if (!Path.IsPathFullyQualified(path) || Path.GetFullPath(path) != path ||
            !StringComparer.OrdinalIgnoreCase.Equals(assembly.Location, path) || Path.GetFileName(path) != assembly.GetName().Name + ".dll") { throw Invalid(); }
        using var held = SecureLocalFile.OpenReadShared(path);
        if (!SecureLocalFile.HandleResolvesToApprovedPath(held, path) || Convert.ToHexStringLower(SHA256.HashData(held)) != expected) { throw Invalid(); }
        // Independently compare the accepted fixed bundle, rather than allowing
        // the issuer's returned names/signature operands to establish code origin.
        string acceptedPath = Path.Combine(AcceptedBundle, Path.GetFileName(path));
        using var baseline = SecureLocalFile.OpenReadShared(acceptedPath);
        if (!SecureLocalFile.HandleResolvesToApprovedPath(baseline, acceptedPath) || Convert.ToHexStringLower(SHA256.HashData(baseline)) != expected) { throw Invalid(); }
    }

    private static void RequireAcceptedCodeOrigin(Assembly assembly)
    {
        string path = Path.Combine(AcceptedBundle, assembly.GetName().Name + ".dll");
        SecureLocalFile.EnsureOwnerOnlyDirectory(AcceptedBundle);
        if (!SecureLocalFile.IsOwnerOnlyFile(new FileInfo(path))) { throw Invalid(); }
        using var held = SecureLocalFile.OpenReadShared(path);
        if (!SecureLocalFile.HandleResolvesToApprovedPath(held, path)) { throw Invalid(); }
        RequireImage(assembly, assembly.Location, Convert.ToHexStringLower(SHA256.HashData(held)));
    }

    private static string Facts(CurrentAuthArchiveGenuineAttestation value)
    {
        return CurrentAuthLocalSessionArchivePolicy.Hash(new
        {
            value.Phase,
            value.CaseId,
            value.Scope,
            value.Subject,
            SourceSha256 = SchemaPlanCanonicalizer.ComputeSha256(value.Source),
            value.TestImagePath,
            value.ConsoleImagePath,
            value.CoreImagePath,
            value.Pins,
        });
    }

    private static MigrationExecutionException Invalid()
    {
        return new("current_auth_archive_genuine_capability_invalid",
        "The fixed Console-owned disposable archive capability is missing, changed, expired or already consumed.");
    }
}

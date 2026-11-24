using System.Reflection;
using System.Runtime.Loader;
using System.Security.Cryptography;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

internal sealed partial class CurrentAuthLocalSessionArchivePermit
{
    // Lexical nesting is the sole private-constructor bridge. No permit escapes this capability.
    internal sealed partial class GenuineExecutionCapability
    {
        private const string IssuerName = "Legacy.Maliev.DataMigration.Console.CurrentAuthArchiveGenuineExecutionIssuer";
        private const string EnvironmentName = "Legacy.Maliev.DataMigration.Console.CurrentAuthLocalSessionArchiveEnvironment";
        private const string AcceptedBundle = @"B:\maliev-legacy\Legacy.Maliev.DataMigration\tests\Legacy.Maliev.DataMigration.Tests\bin\Release\net10.0";
        private readonly object _issuer;
        private readonly Guid _id;
        private readonly CurrentAuthArchiveGenuineExecutionAttestation _binding;
        private readonly string _facts;
        private readonly MethodInfo _require, _reserve;
        private int _state;

        private GenuineExecutionCapability(object issuer, Guid id, CurrentAuthArchiveGenuineExecutionAttestation binding,
            MethodInfo require, MethodInfo reserve)
        { _issuer = issuer; _id = id; _binding = binding; _facts = Facts(binding); _require = require; _reserve = reserve; }

        internal static async Task<GenuineExecutionCapability> AuthenticateAsync(object issuer, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested(); ArgumentNullException.ThrowIfNull(issuer);
            Type type = issuer.GetType();
            if (!type.IsSealed || type.FullName != IssuerName || type.Assembly.GetName().Name != "Legacy.Maliev.DataMigration.Console" ||
                AssemblyLoadContext.GetLoadContext(type.Assembly) != AssemblyLoadContext.Default ||
                type.GetConstructors(BindingFlags.Public | BindingFlags.Instance).Length != 0) { throw Invalid(); }
            // Authenticate code before the first reflected invocation, independently of any returned seed.
            RequireAcceptedOrigin(type.Assembly); RequireAcceptedOrigin(typeof(GenuineExecutionCapability).Assembly);
            MethodInfo mint = Fixed(type, "MintExecutionAsync", typeof(Task<CurrentAuthArchiveGenuineExecutionAttestation>), [typeof(Guid), typeof(CancellationToken)]);
            MethodInfo require = Fixed(type, "RequireExecutionAsync", typeof(Task<CurrentAuthArchiveGenuineExecutionAttestation>), [typeof(Guid), typeof(bool), typeof(CancellationToken)]);
            MethodInfo reserve = Fixed(type, "ReserveExecutionAsync", typeof(Task), [typeof(Guid), typeof(CancellationToken)]);
            Guid id = Guid.NewGuid();
            var binding = await Invoke<CurrentAuthArchiveGenuineExecutionAttestation>(issuer, mint, [id, ct]);
            RequireBinding(issuer, binding);
            return new(issuer, id, binding, require, reserve);
        }

        private async Task RequireAsync(CancellationToken ct)
        {
            if (Volatile.Read(ref _state) == 2) { throw Invalid(); }
            var actual = await Invoke<CurrentAuthArchiveGenuineExecutionAttestation>(_issuer, _require, [_id, Volatile.Read(ref _state) == 0, ct]);
            RequireBinding(_issuer, actual);
            if (Facts(actual) != _facts || !ReferenceEquals(actual.Owned.Environment, _binding.Owned.Environment) ||
                !ReferenceEquals(actual.Owned.Trust, _binding.Owned.Trust) || Volatile.Read(ref _state) == 2) { throw Invalid(); }
        }

        internal async Task<CurrentAuthArchiveGenuineExecutionMethodResult> ExecuteAsync(CancellationToken ct)
        {
            if (_binding.Case == CurrentAuthArchiveGenuineExecutionCase.CommitAcknowledgmentLost) { return await ExecuteCommitAckLostAsync(ct); }
            if (CurrentAuthArchiveGenuineDrift.IsCase(_binding.Case)) { return await ExecuteDriftAsync(ct); }
            if (CurrentAuthArchiveGenuinePublicationFault.IsCase(_binding.Case)) { return await ExecutePublicationFailureAsync(ct); }
            CurrentAuthLocalSessionArchivePermit? permit = null;
            try
            {
                await RequireAsync(ct);
                if (Interlocked.CompareExchange(ref _state, 1, 0) != 0) { throw Invalid(); }
                var reservation = _reserve.Invoke(_issuer, [_id, ct]) as Task ?? throw Invalid();
                await reservation.ConfigureAwait(false); await RequireAsync(ct);
                var owned = _binding.Owned;
                CurrentAuthArchiveScope scope = Claims(_binding.Claims.Review, _binding.Claims.Authorization, owned.Trust, owned.Pins, DateTimeOffset.UtcNow);
                if (CurrentAuthLocalSessionArchivePolicy.Hash(scope) != CurrentAuthLocalSessionArchivePolicy.Hash(owned.Scope)) { throw Invalid(); }
                permit = new(_binding.Claims.Review, _binding.Claims.Authorization, scope, owned.Trust, owned.Pins, owned.Environment, TimeProvider.System);
                // These getters exist only on the already authenticated factory-owned issuer.
                // Neither material is returned to the runner or accepted from configuration.
                string connection = await Invoke<string>(_issuer, Fixed(_issuer.GetType(), "ReadExecutionConnectionAsync", typeof(Task<string>),
                    [typeof(Guid), typeof(CancellationToken)]), [_id, ct]);
                using var signer = await Invoke<P256MigrationEvidenceSigner>(_issuer, Fixed(_issuer.GetType(), "CreateExecutionSignerAsync", typeof(Task<P256MigrationEvidenceSigner>),
                    [typeof(Guid), typeof(CancellationToken)]), [_id, ct]);
                var endpoint = new NpgsqlConnectionStringBuilder(connection);
                if (endpoint.Host != "127.0.0.1" || endpoint.Database != "Auth" || endpoint.Port is < 1 or > 65535 ||
                    endpoint.Username != scope.LocalObservationPolicy.Maintenance.Role || string.IsNullOrWhiteSpace(endpoint.Password) ||
                    !string.IsNullOrEmpty(endpoint.Options) || endpoint.Pooling) { throw Invalid(); }
                permit.RequireEvidenceSigner(signer); await RequireAsync(ct);
                DateTimeOffset began = DateTimeOffset.UtcNow;
                var before = await owned.Environment.CaptureLocalFleetAsync(scope, ct);
                var comparisonBefore = await owned.Environment.CaptureProductionFleetAsync(scope, ct);
                CurrentAuthLocalSessionArchivePolicy.RequireFleet(before, scope.LocalObservationPolicy, DateTimeOffset.UtcNow);
                CurrentAuthLocalSessionArchivePolicy.RequireFleet(comparisonBefore, scope.ProductionObservationPolicy, DateTimeOffset.UtcNow, comparison: true);
                CurrentAuthArchiveReceipt terminal = await PostgreSqlCurrentAuthLocalSessionArchive.ExecuteAsync(connection, permit, signer, ct);
                var after = await owned.Environment.CaptureLocalFleetAsync(scope, ct);
                var comparisonAfter = await owned.Environment.CaptureProductionFleetAsync(scope, ct);
                CurrentAuthLocalSessionArchiveObservation.RequireDeletedOnly(before.Auth, after.Auth);
                CurrentAuthLocalSessionArchivePolicy.RequireFleet(after, scope.LocalObservationPolicy, DateTimeOffset.UtcNow, allowEmptyLocalSessions: true);
                CurrentAuthLocalSessionArchivePolicy.RequireFleet(comparisonAfter, scope.ProductionObservationPolicy, DateTimeOffset.UtcNow, comparison: true);
                if (terminal.Classification != CurrentAppOwnedCommitClassification.CommittedAndReadback || terminal.BeforeAuthSha256 != before.Auth.Native.Snapshot.Sha256 ||
                    terminal.AfterAuthSha256 != after.Auth.Native.Snapshot.Sha256) { throw Invalid(); }
                await RequireAsync(ct);
                var facts = new CurrentAuthArchiveGenuineExecutionFacts(_binding.Case, _binding.Claims, terminal,
                    before, after, comparisonBefore, comparisonAfter, began, DateTimeOffset.UtcNow);
                // The receiver takes final native captures, then closes only Env before copying the original journals.
                var artifacts = await Invoke<CurrentAuthArchiveGenuineDualArtifacts>(_issuer, Fixed(_issuer.GetType(), "RetainExecutionAsync", typeof(Task<CurrentAuthArchiveGenuineDualArtifacts>),
                    [typeof(Guid), typeof(CurrentAuthArchiveGenuineExecutionFacts), typeof(CancellationToken)]), [_id, facts, ct]);
                return artifacts.BeganAtUtc != began || artifacts.EndedAtUtc < began || artifacts.EndedAtUtc > DateTimeOffset.UtcNow
                    ? throw Invalid()
                    : new(0, began, DateTimeOffset.UtcNow, artifacts);
            }
            finally { permit?.Stop(); _ = Interlocked.Exchange(ref _state, 2); }
        }

        private static void RequireBinding(object issuer, CurrentAuthArchiveGenuineExecutionAttestation binding)
        {
            if (binding is null || binding.Owned is null || binding.Claims is null) { throw Invalid(); }
            CurrentAuthArchiveGenuineExecutionCases.RequireImplemented(binding.Case);
            var (Phase, CaseId) = CurrentAuthArchiveGenuineExecutionCases.Identity(binding.Case); var owned = binding.Owned;
            DateTimeOffset now = DateTimeOffset.UtcNow;
            if (owned.Phase != Phase || owned.CaseId != CaseId || owned.Subject != owned.Scope.ComponentSubject ||
                owned.Subject.Seed.CaseId != CaseId || binding.AuthorizationSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(binding.Claims.Authorization)) { throw Invalid(); }
            CurrentAuthArchiveGenuineExecutionSeed.RequireInitial(owned.Subject.Seed, owned.Pins, owned.Trust, binding.Case, now);
            CurrentAuthArchiveScope claims = Claims(binding.Claims.Review, binding.Claims.Authorization, owned.Trust, owned.Pins, now);
            if (CurrentAuthLocalSessionArchivePolicy.Hash(claims) != CurrentAuthLocalSessionArchivePolicy.Hash(owned.Scope)) { throw Invalid(); }
            RequireImage(issuer.GetType().Assembly, owned.ConsoleImagePath, owned.Subject.Seed.ConsoleAssemblySha256);
            RequireImage(typeof(GenuineExecutionCapability).Assembly, owned.CoreImagePath, owned.Subject.Seed.CoreAssemblySha256);
            Assembly[] tests = AppDomain.CurrentDomain.GetAssemblies().Where(value => value.GetName().Name == "Legacy.Maliev.DataMigration.Tests").ToArray();
            if (tests.Length != 1) { throw Invalid(); }
            RequireImage(tests[0], owned.TestImagePath, owned.Subject.Seed.TestAssemblySha256);
            Type environment = owned.Environment.GetType();
            if (!environment.IsSealed || environment.FullName != EnvironmentName || environment.Assembly != issuer.GetType().Assembly ||
                owned.Source.SourceCommitSha != owned.Subject.Seed.AcceptedSourceCommitSha ||
                SchemaPlanCanonicalizer.ComputeSha256(owned.Source) != owned.Subject.Seed.SourceSchemaPlanSha256 ||
                owned.Source.CapturedAtUtc.Offset != TimeSpan.Zero || owned.Source.CapturedAtUtc > now || now - owned.Source.CapturedAtUtc > TimeSpan.FromMinutes(5)) { throw Invalid(); }
        }

        private static string Facts(CurrentAuthArchiveGenuineExecutionAttestation binding)
        {
            return CurrentAuthLocalSessionArchivePolicy.Hash(new
            {
                binding.Case,
                binding.Claims,
                binding.AuthorizationSha256,
                binding.Owned.Phase,
                binding.Owned.CaseId,
                binding.Owned.Scope,
                binding.Owned.Subject,
                Source = SchemaPlanCanonicalizer.ComputeSha256(binding.Owned.Source),
                binding.Owned.TestImagePath,
                binding.Owned.ConsoleImagePath,
                binding.Owned.CoreImagePath,
                binding.Owned.Pins
            });
        }

        private static MethodInfo Fixed(Type type, string name, Type result, Type[] parameters)
        {
            MethodInfo method = type.GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.DeclaredOnly,
                binder: null, types: parameters, modifiers: null) ?? throw Invalid();
            return method.ReturnType == result ? method : throw Invalid();
        }
        private static async Task<T> Invoke<T>(object issuer, MethodInfo method, object[] arguments)
        {
            return await (method.Invoke(issuer, arguments) as Task<T> ?? throw Invalid()).ConfigureAwait(false);
        }

        private static void RequireAcceptedOrigin(Assembly assembly)
        {
            SecureLocalFile.EnsureOwnerOnlyDirectory(AcceptedBundle);
            string path = Path.Combine(AcceptedBundle, assembly.GetName().Name + ".dll");
            if (!SecureLocalFile.IsOwnerOnlyFile(new FileInfo(path))) { throw Invalid(); }
            using var held = SecureLocalFile.OpenReadShared(path);
            if (!SecureLocalFile.HandleResolvesToApprovedPath(held, path)) { throw Invalid(); }
            RequireImage(assembly, assembly.Location, Convert.ToHexStringLower(SHA256.HashData(held)));
        }
        private static void RequireImage(Assembly assembly, string path, string expected)
        {
            if (!Path.IsPathFullyQualified(path) || Path.GetFullPath(path) != path ||
                !StringComparer.OrdinalIgnoreCase.Equals(assembly.Location, path) || Path.GetFileName(path) != assembly.GetName().Name + ".dll") { throw Invalid(); }
            using var held = SecureLocalFile.OpenReadShared(path);
            using var baseline = SecureLocalFile.OpenReadShared(Path.Combine(AcceptedBundle, Path.GetFileName(path)));
            if (!SecureLocalFile.HandleResolvesToApprovedPath(held, path) || !SecureLocalFile.HandleResolvesToApprovedPath(baseline, Path.Combine(AcceptedBundle, Path.GetFileName(path))) ||
                Convert.ToHexStringLower(SHA256.HashData(held)) != expected || Convert.ToHexStringLower(SHA256.HashData(baseline)) != expected) { throw Invalid(); }
        }
        private static MigrationExecutionException Invalid()
        {
            return CurrentAuthArchiveGenuineExecutionCases.Invalid();
        }
    }
}

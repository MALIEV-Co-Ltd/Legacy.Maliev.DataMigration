using System.Reflection;
using System.Runtime.Loader;

namespace Legacy.Maliev.DataMigration;

internal sealed partial class CurrentAuthLocalSessionArchivePermit
{
    private Final6PersistentCapability? _final6Persistent;
    internal sealed class Final6PersistentCapability
    {
        private const string Issuer = "Legacy.Maliev.DataMigration.Console.CurrentAuthArchiveFinal6PersistentIssuer";
        private readonly object _issuer;
        private readonly Guid _id;
        private readonly CurrentAuthArchiveFinal6PersistentAttestation _binding;
        private readonly MethodInfo _require, _writer;
        private readonly string _facts;
        private int _state;
        private Final6PersistentCapability(object issuer, Guid id, CurrentAuthArchiveFinal6PersistentAttestation binding, MethodInfo require, MethodInfo writer)
        { _issuer = issuer; _id = id; _binding = binding; _require = require; _writer = writer; _facts = Facts(binding); }
        internal static async Task<Final6PersistentCapability> AuthenticateAsync(object issuer, CancellationToken ct)
        {
            ArgumentNullException.ThrowIfNull(issuer); ct.ThrowIfCancellationRequested();
            Type type = issuer.GetType();
            if (!type.IsSealed || type.FullName != Issuer || type.Assembly.GetName().Name != "Legacy.Maliev.DataMigration.Console" ||
                AssemblyLoadContext.GetLoadContext(type.Assembly) != AssemblyLoadContext.Default || type.GetConstructors(BindingFlags.Instance | BindingFlags.Public).Length != 0)
            { throw CurrentAuthArchiveFinal6PersistentPolicy.Invalid(); }
            CurrentAuthArchiveGenuineCapability.RequirePersistentArchiveCodeOrigin(type.Assembly);
            CurrentAuthArchiveGenuineCapability.RequirePersistentArchiveCodeOrigin(typeof(Final6PersistentCapability).Assembly);
            var mint = Fixed(type, "MintFinal6PersistentAsync", typeof(Task<CurrentAuthArchiveFinal6PersistentAttestation>));
            var require = Fixed(type, "RequireFinal6PersistentAsync", typeof(Task<CurrentAuthArchiveFinal6PersistentAttestation>));
            var writer = Fixed(type, "GetFinal6PersistentWriterAsync", typeof(Task<string>));
            Guid id = Guid.NewGuid();
            var binding = await Invoke<CurrentAuthArchiveFinal6PersistentAttestation>(issuer, mint, id, ct);
            RequireBinding(issuer, binding);
            return new(issuer, id, binding, require, writer);
        }
        internal async Task<CurrentAuthArchiveReceipt> ExecuteAsync(P256MigrationEvidenceSigner signer, CancellationToken ct)
        {
            if (Interlocked.CompareExchange(ref _state, 1, 0) != 0) { throw CurrentAuthArchiveFinal6PersistentPolicy.Invalid(); }
            CurrentAuthLocalSessionArchivePermit? permit = null;
            try
            {
                permit = new(_binding.Review, _binding.Authorization, _binding.Intent.Scope, _binding.Trust, _binding.Pins, _binding.Environment, TimeProvider.System)
                { _final6Persistent = this };
                await permit.RequireAsync(ct); _ = await permit.RequireOriginalFleetsAsync(ct);
                string writer = await Invoke<string>(_issuer, _writer, _id, ct);
                return await PostgreSqlCurrentAuthLocalSessionArchive.ExecuteAsync(writer, permit, signer, ct);
            }
            finally { permit?.Stop(); _ = Interlocked.Exchange(ref _state, 2); }
        }
        internal async Task RequirePermitAsync(CurrentAuthLocalSessionArchivePermit permit, CancellationToken ct)
        {
            if (Volatile.Read(ref _state) != 1 || !ReferenceEquals(permit.Environment, _binding.Environment) ||
                CurrentAuthLocalSessionArchivePolicy.Hash(permit.Scope) != CurrentAuthLocalSessionArchivePolicy.Hash(_binding.Intent.Scope)) { throw CurrentAuthArchiveFinal6PersistentPolicy.Invalid(); }
            var actual = await Invoke<CurrentAuthArchiveFinal6PersistentAttestation>(_issuer, _require, _id, ct);
            RequireBinding(_issuer, actual);
            if (!ReferenceEquals(actual.Environment, _binding.Environment) || !ReferenceEquals(actual.Trust, _binding.Trust) || Facts(actual) != _facts)
            { throw CurrentAuthArchiveFinal6PersistentPolicy.Invalid(); }
        }
        internal void RequireFleets(CurrentAuthArchiveFleet local, CurrentAuthArchiveFleet comparison)
        {
            CurrentAuthArchiveFinal6PersistentPolicy.RequireFleets(_binding.Intent, local, comparison);
        }

        internal async Task VerifyAsync(CancellationToken ct)
        {
            if (Interlocked.CompareExchange(ref _state, 1, 0) != 0) { throw CurrentAuthArchiveFinal6PersistentPolicy.Invalid(); }
            var permit = new CurrentAuthLocalSessionArchivePermit(_binding.Review, _binding.Authorization, _binding.Intent.Scope,
                _binding.Trust, _binding.Pins, _binding.Environment, TimeProvider.System)
            { _final6Persistent = this };
            try { await permit.RequireAsync(ct); _ = await permit.RequireOriginalFleetsAsync(ct); }
            finally { permit.Stop(); _ = Interlocked.Exchange(ref _state, 2); }
        }
        private static void RequireBinding(object issuer, CurrentAuthArchiveFinal6PersistentAttestation binding)
        {
            CurrentAuthArchiveFinal6Source.RequireProfiles(binding.Source, DateTimeOffset.UtcNow);
            var actual = CurrentAuthArchiveFinal6PersistentPolicy.Claims(binding.Review, binding.Authorization, binding.Pins, binding.Trust, DateTimeOffset.UtcNow);
            Type environment = binding.Environment.GetType();
            if (CurrentAuthLocalSessionArchivePolicy.Hash(actual) != CurrentAuthLocalSessionArchivePolicy.Hash(binding.Intent) ||
                !environment.IsSealed || environment.Assembly != issuer.GetType().Assembly ||
                environment.FullName != "Legacy.Maliev.DataMigration.Console.CurrentAuthLocalSessionArchiveEnvironment" ||
                SchemaPlanCanonicalizer.ComputeSha256(binding.Source) != actual.Scope.LocalObservationPolicy.SourceSchemaPlanSha256)
            { throw CurrentAuthArchiveFinal6PersistentPolicy.Invalid(); }
        }
        private static string Facts(CurrentAuthArchiveFinal6PersistentAttestation value)
        {
            return CurrentAuthLocalSessionArchivePolicy.Hash(new
            { value.Intent, value.Review, value.Authorization, value.Pins, Source = SchemaPlanCanonicalizer.ComputeSha256(value.Source) });
        }

        private static MethodInfo Fixed(Type type, string name, Type result)
        {
            var method = type.GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.DeclaredOnly, null,
                [typeof(Guid), typeof(CancellationToken)], null) ?? throw CurrentAuthArchiveFinal6PersistentPolicy.Invalid();
            return method.ReturnType == result ? method : throw CurrentAuthArchiveFinal6PersistentPolicy.Invalid();
        }
        private static async Task<T> Invoke<T>(object issuer, MethodInfo method, Guid id, CancellationToken ct)
        {
            return await ((Task<T>?)method.Invoke(issuer, [id, ct]) ?? throw CurrentAuthArchiveFinal6PersistentPolicy.Invalid());
        }
    }
}

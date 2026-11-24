using System.Reflection;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

// Scope MUST be absent. The fixed native implementation derives it after initial authentication.
internal sealed record CurrentAuthArchiveInitialProducerConfiguration(CurrentAuthArchiveComponentReadbackInput Inputs,
    string FirstFixtureParent, string SecondFixtureParent);

internal static class CurrentAuthArchiveInitialProducer
{
    internal const string Command = "observe-current-auth-archive-initial-pair";
    private const string NativeType = "Legacy.Maliev.DataMigration.Tests.CurrentAuthArchiveInitialNativeProducer";

    internal static void RequireInput(CurrentAuthArchiveInitialProducerConfiguration config)
    {
        if (config is null || config.Inputs is null || config.Inputs.Scope is not null ||
            string.IsNullOrWhiteSpace(config.FirstFixtureParent) || string.IsNullOrWhiteSpace(config.SecondFixtureParent) ||
            !Path.IsPathFullyQualified(config.FirstFixtureParent) || !Path.IsPathFullyQualified(config.SecondFixtureParent) ||
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(config.FirstFixtureParent)) != config.FirstFixtureParent ||
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(config.SecondFixtureParent)) != config.SecondFixtureParent ||
            StringComparer.OrdinalIgnoreCase.Equals(config.FirstFixtureParent, config.SecondFixtureParent))
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        CurrentAuthArchiveComponentReadback.RequireInput(config.Inputs, allowInitialScope: true);
    }

    internal static async Task<CurrentAuthArchiveComponentBootstrapSubject> ObserveAsync(
        CurrentAuthArchiveInitialProducerConfiguration config, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        RequireInput(config);
        CurrentAuthArchiveCapacity.Require(admission: true);
        _ = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false);
        string root = Path.GetDirectoryName(config.Inputs.TestImage.Path) ?? throw CurrentAuthLocalSessionArchivePolicy.Invalid();
        if (Path.GetFileName(config.Inputs.TestImage.Path) != "Legacy.Maliev.DataMigration.Tests.dll")
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        using var bundle = await CurrentAuthTypedHostProducer.HoldFixedTestBundleAsync(root, ct).ConfigureAwait(false);
        using var context = new FixedNativeBundle(config.Inputs.TestImage.Path);
        try
        {
            Assembly tests = context.LoadFromAssemblyPath(config.Inputs.TestImage.Path);
            MethodInfo method = tests.GetType(NativeType, throwOnError: true)!.GetMethod("ObserveAsync",
                BindingFlags.Static | BindingFlags.NonPublic, binder: null,
                types: [typeof(CurrentAuthArchiveInitialProducerConfiguration), typeof(CancellationToken)], modifiers: null)
                ?? throw CurrentAuthLocalSessionArchivePolicy.Invalid();
            bundle.Require();
            var task = method.Invoke(null, [config, ct]) as Task<CurrentAuthArchiveComponentBootstrapSubject>
                ?? throw CurrentAuthLocalSessionArchivePolicy.Invalid();
            CurrentAuthArchiveComponentBootstrapSubject observed = await task.ConfigureAwait(false);
            bundle.Require();
            return observed;
        }
        finally { context.Unload(); }
    }

    // Pure predicates only; runtime derives these roots from accepted running and held test bundles.
    internal static string RequireBundleOrigin(string? path, string root)
    {
        string prefix = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root)) + Path.DirectorySeparatorChar;
        return string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) ||
            !StringComparer.OrdinalIgnoreCase.Equals(path, Path.GetFullPath(path)) ||
            !path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
            ? throw CurrentAuthLocalSessionArchivePolicy.Invalid() : path;
    }

    internal static void RequireSharedDependencyBytes(Stream running, Stream test)
    {
        running.Position = 0; test.Position = 0;
        if (running.Length != test.Length || running.Length is < 1 or > 128 * 1024 * 1024 ||
            !CryptographicOperations.FixedTimeEquals(SHA256.HashData(running), SHA256.HashData(test)))
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        running.Position = 0; test.Position = 0;
    }

    // The accepted resolved assembly may roll forward, as the CLR does. Missing requested
    // versions impose no minimum; missing actual versions and unspecified tokens are not wildcards.
    internal static bool CompatibleManagedIdentity(AssemblyName requested, AssemblyName actual)
    {
        return !string.IsNullOrWhiteSpace(requested.Name) && !string.IsNullOrWhiteSpace(actual.Name) &&
            StringComparer.OrdinalIgnoreCase.Equals(requested.Name, actual.Name) &&
            StringComparer.OrdinalIgnoreCase.Equals(requested.CultureName ?? string.Empty, actual.CultureName ?? string.Empty) &&
            (requested.GetPublicKeyToken() ?? []).AsSpan().SequenceEqual(actual.GetPublicKeyToken() ?? []) &&
            requested.ContentType == actual.ContentType && actual.Version is not null &&
            (requested.Version is null || actual.Version.CompareTo(requested.Version) >= 0);
    }

    // Preserve cross-ALC API type identity only with verified origins and equal held bytes.
    internal sealed class FixedNativeBundle : AssemblyLoadContext, IDisposable
    {
        private readonly AssemblyDependencyResolver _resolver;
        private readonly string _testRoot;
        private readonly Dictionary<string, FileStream> _held = new(StringComparer.OrdinalIgnoreCase);
        private readonly Lock _gate = new();
        private static string FrameworkRoot => Path.GetDirectoryName(typeof(object).Assembly.Location)
            ?? throw CurrentAuthLocalSessionArchivePolicy.Invalid();

        internal FixedNativeBundle(string image) : base(isCollectible: true)
        {
            _testRoot = Path.GetDirectoryName(image) ?? throw CurrentAuthLocalSessionArchivePolicy.Invalid();
            _resolver = new(image);
        }

        protected override Assembly? Load(AssemblyName name)
        {
            string? frameworkPath = FrameworkPath(name);
            Assembly? shared = Default.Assemblies.SingleOrDefault(x => CompatibleManagedIdentity(name, x.GetName()));
            if (frameworkPath is not null)
            {
                if (shared is not null && (!StringComparer.OrdinalIgnoreCase.Equals(shared.Location, frameworkPath) ||
                    shared.GetName().FullName != AssemblyName.GetAssemblyName(frameworkPath).FullName))
                { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
                _ = Hold(frameworkPath, framework: true);
                return shared ?? Default.LoadFromAssemblyPath(frameworkPath);
            }
            if (shared is not null)
            {
                if ((name.Name == typeof(MigrationConsole).Assembly.GetName().Name && shared != typeof(MigrationConsole).Assembly) ||
                    (name.Name == typeof(DeltaExecutionCoordinator).Assembly.GetName().Name && shared != typeof(DeltaExecutionCoordinator).Assembly))
                { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
                string runningPath = RequireBundleOrigin(shared.Location, AppContext.BaseDirectory);
                string testPath = RequireBundleOrigin(Path.Combine(_testRoot, Path.GetRelativePath(AppContext.BaseDirectory, runningPath)), _testRoot);
                lock (_gate) { RequireSharedDependencyBytes(Hold(runningPath), Hold(testPath)); }
                return AssemblyName.GetAssemblyName(runningPath).FullName != shared.GetName().FullName
                    ? throw CurrentAuthLocalSessionArchivePolicy.Invalid()
                    : shared;
            }
            string path = RequireBundleOrigin(_resolver.ResolveAssemblyToPath(name), _testRoot);
            if (!CompatibleManagedIdentity(name, AssemblyName.GetAssemblyName(path))) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            // A shared API dependency may not have loaded yet. Prefer its verified Console
            // copy now, so later Core/Console calls cannot load a second Npgsql identity.
            string candidate = RequireBundleOrigin(Path.Combine(AppContext.BaseDirectory, Path.GetRelativePath(_testRoot, path)), AppContext.BaseDirectory);
            if (File.Exists(candidate))
            {
                if (!CompatibleManagedIdentity(name, AssemblyName.GetAssemblyName(candidate))) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
                lock (_gate) { RequireSharedDependencyBytes(Hold(candidate), Hold(path)); }
                return Default.LoadFromAssemblyPath(candidate);
            }
            _ = Hold(path);
            return LoadFromAssemblyPath(path);
        }

        protected override nint LoadUnmanagedDll(string unmanagedDllName)
        {
            string path = RequireBundleOrigin(_resolver.ResolveUnmanagedDllToPath(unmanagedDllName), _testRoot);
            _ = Hold(path);
            return LoadUnmanagedDllFromPath(path);
        }

        private static string? FrameworkPath(AssemblyName name)
        {
            if (string.IsNullOrWhiteSpace(name.Name) || Path.GetFileName(name.Name) != name.Name)
            { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            string path = Path.Combine(FrameworkRoot, name.Name + ".dll");
            return File.Exists(path) && CompatibleManagedIdentity(name, AssemblyName.GetAssemblyName(path)) ? path : null;
        }

        private FileStream Hold(string path, bool framework = false)
        {
            lock (_gate)
            {
                if (_held.TryGetValue(path, out FileStream? existing)) { return existing; }
                // OS framework files are outside run custody; their directory is derived from actual CoreLib.
                FileStream stream = framework ? new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read) : SecureLocalFile.OpenReadShared(path);
                try
                {
                    if (!framework && !SecureLocalFile.HandleResolvesToApprovedPath(stream, path))
                    { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
                    _held.Add(path, stream); return stream;
                }
                catch { stream.Dispose(); throw; }
            }
        }

        public void Dispose()
        {
            lock (_gate) { foreach (FileStream stream in _held.Values) { stream.Dispose(); } _held.Clear(); }
        }
    }
}

public static partial class MigrationConsole
{
    private static async Task<int> RunCurrentAuthArchiveInitialProducerAsync(string configPath, TextWriter output, TextWriter error, CancellationToken ct)
    {
        using var lease = CancellationTokenSource.CreateLinkedTokenSource(ct); lease.CancelAfter(TimeSpan.FromMinutes(8));
        try
        {
            var config = await ReadProtectedJsonAsync<CurrentAuthArchiveInitialProducerConfiguration>(configPath,
                "current_auth_archive_initial_config_unprotected", lease.Token).ConfigureAwait(false);
            _ = await CurrentAuthArchiveInitialProducer.ObserveAsync(config, lease.Token).ConfigureAwait(false);
            await output.WriteLineAsync("current_auth_archive_pair_observed_no_execution_authority").ConfigureAwait(false);
            return 0;
        }
        catch (Exception failure) when (failure is MigrationExecutionException or IOException or UnauthorizedAccessException or
            JsonException or ArgumentException or InvalidOperationException or TargetInvocationException or OperationCanceledException)
        {
            await error.WriteLineAsync("current_auth_archive_initial_pair_failed_no_proof").ConfigureAwait(false);
            return 1;
        }
    }
}

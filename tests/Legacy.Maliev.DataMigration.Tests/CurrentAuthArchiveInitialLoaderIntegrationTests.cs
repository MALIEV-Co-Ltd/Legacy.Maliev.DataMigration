using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;
using System.Runtime.Loader;
using Legacy.Maliev.DataMigration.Console;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

// Managed loader/type-identity mechanics only. No producer, fixture, source admission or database is invoked.
[Collection(LocalSnapshotIoTestGroup.Name)]
public sealed class CurrentAuthArchiveInitialLoaderIntegrationTests
{
    [WindowsLocalRunFact]
    public void Cloned_test_bundle_shares_cross_boundary_types_and_rolls_forward_accepted_dependencies()
    {
        if (!OperatingSystem.IsWindows()) { return; }
        string source = Path.TrimEndingDirectorySeparator(Path.GetFullPath(AppContext.BaseDirectory));
        foreach (Assembly assembly in new[] { typeof(DeltaExecutionCoordinator).Assembly, typeof(MigrationConsole).Assembly, typeof(NpgsqlConnection).Assembly })
        {
            Assert.Same(AssemblyLoadContext.Default, AssemblyLoadContext.GetLoadContext(assembly));
            Assert.True(SecureLocalFile.IsOwnerOnlyFile(new FileInfo(assembly.Location)),
                "This integration check requires an owner-protected running test bundle; it never changes its permissions.");
        }
        string temp = Path.TrimEndingDirectorySeparator(Path.GetFullPath(Path.GetTempPath()));
        string root = Path.Combine(temp, "archive-loader-integration-" + Guid.NewGuid().ToString("N"));
        bool created = false;
        WeakReference? unloaded = null;
        var failures = new List<Exception>();
        try
        {
            Assert.False(Directory.Exists(root));
            SecureSnapshotFileCreation.CreateRestrictedDirectory(root); created = true;
            CopyRuntimeAssets(source, root);
            string image = Path.Combine(root, "Legacy.Maliev.DataMigration.Tests.dll");
            Assert.True(File.Exists(image));
            LoadAndAssert(image, out unloaded);
        }
        catch (Exception failure) { failures.Add(failure); }
        finally
        {
            try
            {
                try
                {
                    // A collectible context's OS image handles settle only after its unreachable loader is collected.
                    if (unloaded is not null)
                    {
                        for (int attempt = 0; unloaded.IsAlive && attempt < 10; attempt++)
                        { GC.Collect(); GC.WaitForPendingFinalizers(); }
                        Assert.False(unloaded.IsAlive, "The disposable loader must unload before its exact copied bundle is removed.");
                    }
                }
                catch (Exception failure) { failures.Add(failure); }
            }
            finally
            {
                try
                {
                    if (created)
                    {
                        string resolved = Path.GetFullPath(root);
                        Assert.StartsWith(temp + Path.DirectorySeparatorChar + "archive-loader-integration-", resolved, StringComparison.OrdinalIgnoreCase);
                        SecureSnapshotFileCreation.ValidateRestrictedDirectory(resolved);
                        Directory.Delete(resolved, recursive: true);
                        Assert.False(Directory.Exists(resolved));
                    }
                }
                catch (Exception failure) { failures.Add(failure); }
            }
        }
        if (failures.Count == 1) { ExceptionDispatchInfo.Capture(failures[0]).Throw(); }
        if (failures.Count > 1)
        { throw new AggregateException("Managed loader test failed or could not release its exact copied bundle: " + root, failures); }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void LoadAndAssert(string image, out WeakReference? unloaded)
    {
        unloaded = null;
        Type loader = typeof(CurrentAuthArchiveInitialProducer).GetNestedType("FixedNativeBundle", BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("The fixed production loader is missing.");
        var context = (AssemblyLoadContext)(Activator.CreateInstance(loader, BindingFlags.Instance | BindingFlags.NonPublic,
            binder: null, args: [image], culture: null) ?? throw new InvalidOperationException("The fixed loader could not be created."));
        unloaded = new WeakReference(context);
        try
        {
            Assembly clone = context.LoadFromAssemblyPath(image);
            Assert.NotSame(typeof(CurrentAuthArchiveInitialLoaderIntegrationTests).Assembly, clone);
            Assert.Same(context, AssemblyLoadContext.GetLoadContext(clone));
            Assert.Equal(Path.GetFullPath(image), clone.Location);
            Assert.Same(typeof(DeltaExecutionCoordinator).Assembly, context.LoadFromAssemblyName(typeof(DeltaExecutionCoordinator).Assembly.GetName()));
            Assert.Same(typeof(MigrationConsole).Assembly, context.LoadFromAssemblyName(typeof(MigrationConsole).Assembly.GetName()));
            Assert.Same(typeof(NpgsqlConnection).Assembly, context.LoadFromAssemblyName(typeof(NpgsqlConnection).Assembly.GetName()));

            MethodInfo boundary = clone.GetType("Legacy.Maliev.DataMigration.Tests.CurrentAuthArchiveFixturePolicy", throwOnError: true)!
                .GetMethod("RequireInstalledAsync", BindingFlags.Static | BindingFlags.NonPublic)!;
            ParameterInfo[] parameters = boundary.GetParameters();
            Assert.Equal(typeof(NpgsqlConnection), parameters[0].ParameterType);
            Assert.Equal(typeof(NpgsqlTransaction), parameters[1].ParameterType);
            Assert.Equal(typeof(CurrentAppOwnedMaintenancePin), parameters[2].ParameterType);

            MethodInfo entry = clone.GetType("Legacy.Maliev.DataMigration.Tests.CurrentAuthArchiveInitialNativeProducer", throwOnError: true)!
                .GetMethod("ObserveAsync", BindingFlags.Static | BindingFlags.NonPublic)!;
            Assert.Equal(typeof(CurrentAuthArchiveInitialProducerConfiguration), entry.GetParameters()[0].ParameterType);
            Assert.Equal(typeof(Task<CurrentAuthArchiveComponentBootstrapSubject>), entry.ReturnType);

            Assembly logging = context.LoadFromAssemblyName(new("Microsoft.Extensions.Logging.Abstractions, Version=8.0.0.0, Culture=neutral, PublicKeyToken=adb9793829ddae60"));
            Assert.Equal(new Version(10, 0, 0, 0), logging.GetName().Version);
            Assert.Same(AssemblyLoadContext.Default, AssemblyLoadContext.GetLoadContext(logging));
            Assert.Same(logging, AssemblyLoadContext.Default.LoadFromAssemblyName(logging.GetName()));
            Assembly runtime = context.LoadFromAssemblyName(new("System.Runtime, Version=6.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"));
            Assert.Equal(new Version(10, 0, 0, 0), runtime.GetName().Version);
            Assert.Same(AssemblyLoadContext.Default, AssemblyLoadContext.GetLoadContext(runtime));
            Assert.Equal(Path.GetDirectoryName(typeof(object).Assembly.Location), Path.GetDirectoryName(runtime.Location));

            Exception? rejection = Record.Exception(() => context.LoadFromAssemblyName(new("Maliev.Archive.Unresolved.LoaderThreat, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null")));
            Assert.NotNull(rejection);
            Assert.True(ContainsGuardFailure(rejection), "Unresolved code must hit the production guard rather than default-context fallback.");
        }
        finally { try { context.Unload(); } finally { ((IDisposable)context).Dispose(); } }
    }

    private static bool ContainsGuardFailure(Exception? failure)
    {
        for (; failure is not null; failure = failure.InnerException)
        { if (failure is MigrationExecutionException { Code: "current_auth_local_archive_invalid" }) { return true; } }
        return false;
    }

    private static void CopyRuntimeAssets(string source, string root)
    {
        foreach (string path in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories).Where(path =>
            path.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) || path.EndsWith(".deps.json", StringComparison.OrdinalIgnoreCase) ||
            path.EndsWith(".runtimeconfig.json", StringComparison.OrdinalIgnoreCase)))
        {
            SecureSnapshotFileCreation.RejectLinkedAncestors(Path.GetDirectoryName(path)!);
            Assert.True(SecureLocalFile.IsRegularNonLink(new FileInfo(path)));
            string target = Path.GetFullPath(Path.Combine(root, Path.GetRelativePath(source, path)));
            Assert.StartsWith(root + Path.DirectorySeparatorChar, target, StringComparison.OrdinalIgnoreCase);
            SecureSnapshotFileCreation.CreateRestrictedDirectory(Path.GetDirectoryName(target)!);
            using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            input.CopyTo(output);
        }
    }
}

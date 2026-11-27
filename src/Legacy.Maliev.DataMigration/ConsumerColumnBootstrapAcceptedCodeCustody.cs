using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

/// <summary>Holds independently matched accepted implementation bytes before any environment callback.</summary>
internal sealed class ConsumerColumnBootstrapAcceptedCodeCustody : IDisposable
{
    private const string AcceptedRoot = @"B:\maliev-legacy\Legacy.Maliev.DataMigration\src\Legacy.Maliev.DataMigration.Console\bin\Release\net10.0";
    private readonly List<FileStream> _held = [];
    private bool _disposed;
    internal string RunnerDigestSha256 { get; private set; } = string.Empty;
    private ConsumerColumnBootstrapAcceptedCodeCustody() { }

    internal static ConsumerColumnBootstrapAcceptedCodeCustody Acquire(Type implementation, TimeProvider clock)
    {
        return AcquireNamed(implementation, clock, "Legacy.Maliev.DataMigration.Console.ConsumerColumnBootstrapOperationalEnvironment");
    }

    internal static ConsumerColumnBootstrapAcceptedCodeCustody AcquireCompletion(Type implementation)
    {
        return AcquireNamed(implementation, TimeProvider.System, "Legacy.Maliev.DataMigration.Console.ConsumerColumnBootstrapRehearsalProducer+Completion");
    }

    private static ConsumerColumnBootstrapAcceptedCodeCustody AcquireNamed(Type implementation, TimeProvider clock, string expectedType)
    {
        var console = implementation.Assembly;
        if (!OperatingSystem.IsWindows() || !ReferenceEquals(clock, TimeProvider.System) || !implementation.IsSealed ||
            implementation.FullName != expectedType ||
            console.IsDynamic || Assembly.GetEntryAssembly() != console || console.GetName().Name != "Legacy.Maliev.DataMigration.Console")
        { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        var custody = new ConsumerColumnBootstrapAcceptedCodeCustody();
        try
        {
            string runningRoot = Path.GetDirectoryName(typeof(ConsumerColumnBootstrapOperationalPermit).Assembly.Location)
                ?? throw ConsumerColumnBootstrapOperationalContract.Invalid();
            if (StringComparer.OrdinalIgnoreCase.Equals(Path.GetFullPath(runningRoot), Path.GetFullPath(AcceptedRoot))) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
            Assembly[] assemblies = [console, typeof(ConsumerColumnBootstrapOperationalPermit).Assembly, typeof(NpgsqlConnection).Assembly];
            var identities = new List<(string Name, string Sha256)>();
            foreach (Assembly assembly in assemblies)
            {
                if (assembly.IsDynamic || string.IsNullOrWhiteSpace(assembly.Location) ||
                    !StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(Path.GetFullPath(assembly.Location)), Path.GetFullPath(runningRoot)))
                { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
                string expected = Path.Combine(AcceptedRoot, Path.GetFileName(assembly.Location));
                FileStream accepted = SecureLocalFile.OpenReadShared(expected); custody._held.Add(accepted);
                FileStream actual = SecureLocalFile.OpenReadShared(assembly.Location); custody._held.Add(actual);
                byte[] expectedHash = SHA256.HashData(accepted), actualHash = SHA256.HashData(actual);
                if (!CryptographicOperations.FixedTimeEquals(expectedHash, actualHash))
                { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
                identities.Add((Path.GetFileName(assembly.Location), Convert.ToHexStringLower(actualHash)));
            }
            custody.RunnerDigestSha256 = ConsumerColumnBootstrapOperationalContract.Hash([.. "Legacy.Maliev.ConsumerColumnBootstrap.Runner.v1\0"u8,
                .. JsonSerializer.SerializeToUtf8Bytes(identities.OrderBy(identity => identity.Name, StringComparer.Ordinal).Select(identity => new { identity.Name, identity.Sha256 }).ToArray())]);
            return custody;
        }
        catch { custody.Dispose(); throw; }
    }

    public void Dispose()
    {
        if (_disposed) { return; }
        _disposed = true; foreach (var handle in _held) { handle.Dispose(); }
        _held.Clear();
    }
}

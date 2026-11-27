using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

// Family-specific closed issuer. Does not widen the Bootstrap or Auth implementation whitelist.
internal sealed class OrderSubtotalAcceptedCodeCustody : IDisposable
{
    private const string Accepted = @"B:\maliev-legacy\Legacy.Maliev.DataMigration\src\Legacy.Maliev.DataMigration.Console\bin\Release\net10.0";
    private readonly List<(FileStream Handle, string Path)> _held = [];
    private bool _disposed;
    internal string RunnerDigestSha256 { get; private set; } = string.Empty;
    private OrderSubtotalAcceptedCodeCustody() { }
    internal static OrderSubtotalAcceptedCodeCustody Acquire()
    {
        if (!OperatingSystem.IsWindows() || Assembly.GetEntryAssembly() != typeof(MigrationConsole).Assembly) { throw OrderSubtotalRepairProtocol.Invalid(); }
        var result = new OrderSubtotalAcceptedCodeCustody();
        try
        {
            string actualRoot = Path.GetDirectoryName(typeof(MigrationConsole).Assembly.Location)!;
            if (StringComparer.OrdinalIgnoreCase.Equals(Path.GetFullPath(actualRoot), Path.GetFullPath(Accepted))) { throw OrderSubtotalRepairProtocol.Invalid(); }
            Assembly[] images = [typeof(MigrationConsole).Assembly, typeof(OrderSubtotalRepairProtocol).Assembly, typeof(NpgsqlConnection).Assembly];
            var identities = new List<(string Name, string Sha256)>();
            foreach (Assembly image in images)
            {
                if (image.IsDynamic || !StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(Path.GetFullPath(image.Location)), Path.GetFullPath(actualRoot)))
                { throw OrderSubtotalRepairProtocol.Invalid(); }
                string name = Path.GetFileName(image.Location); string original = Path.Combine(Accepted, name);
                var approved = SecureLocalFile.OpenReadShared(original); result._held.Add((approved, original));
                var actual = SecureLocalFile.OpenReadShared(image.Location); result._held.Add((actual, image.Location));
                byte[] expected = SHA256.HashData(approved), observed = SHA256.HashData(actual);
                if (!CryptographicOperations.FixedTimeEquals(expected, observed)) { throw OrderSubtotalRepairProtocol.Invalid(); }
                identities.Add((name, Convert.ToHexStringLower(observed)));
            }
            result.RunnerDigestSha256 = OrderSubtotalRepairProtocol.Hash([.. "Legacy.Maliev.OrderSubtotal.AcceptedRunner.v1\0"u8,
                .. JsonSerializer.SerializeToUtf8Bytes(identities.OrderBy(x => x.Name, StringComparer.Ordinal).Select(x => new { x.Name, x.Sha256 }))]);
            result.Require(); return result;
        }
        catch { result.Dispose(); throw; }
    }
    internal void Require()
    { ObjectDisposedException.ThrowIf(_disposed, this); foreach (var file in _held) { if (!SecureLocalFile.HandleResolvesToApprovedPath(file.Handle, file.Path)) { throw OrderSubtotalRepairProtocol.Invalid(); } } }
    public void Dispose() { if (_disposed) { return; } _disposed = true; foreach (var file in _held) { file.Handle.Dispose(); } _held.Clear(); }
}

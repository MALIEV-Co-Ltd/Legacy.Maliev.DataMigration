using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthClosedPreparationConfiguration(string RunBindingPath, string SourceSchemaPath,
    string AdminConnectionPath, Guid OperationId, string ContainerId, string CaseId,
    CurrentAuthClosedBootstrapEvidence CompletedComponents, string PrecursorReviewPrivateKeyPath,
    string TestAssemblyPath);

public static partial class MigrationConsole
{
    // Proposed fixed route: prepare-current-auth-named-closed-proof. It is restricted to
    // a fresh exact owned named disposable target. No persistent target is accepted.
    private static async Task<int> RunCurrentAuthClosedPreparationAsync(string configPath,
        TextWriter output, TextWriter error, CancellationToken ct)
    {
        try
        {
            CurrentAuthRepairCapacity.Require(admission: true);
            var config = await ReadProtectedJsonAsync<CurrentAuthClosedPreparationConfiguration>(configPath,
                "current_auth_closed_preparation_config_unprotected", ct).ConfigureAwait(false);
            var binding = await ReadProtectedJsonAsync<LocalExecutionBinding>(config.RunBindingPath,
                "current_auth_closed_preparation_binding_unprotected", ct).ConfigureAwait(false);
            using var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
            using var files = new CurrentAppOwnedRepairCustody(authority);
            if (JsonSerializer.Serialize(DecodeAuthRepair<CurrentAuthClosedPreparationConfiguration>(files.Read(configPath, maximumBytes: 32 * 1024 * 1024))) !=
                JsonSerializer.Serialize(config) || DecodeAuthRepair<LocalExecutionBinding>(files.Read(config.RunBindingPath, maximumBytes: 65536)) != binding)
            { throw CurrentAuthRepairPermit.Invalid(); }
            var source = DecodeAuthRepair<FreshSchemaPlan>(files.Read(config.SourceSchemaPath, maximumBytes: 32 * 1024 * 1024));
            string admin = Encoding.UTF8.GetString(files.Read(config.AdminConnectionPath, maximumBytes: 65536));
            using var lease = CancellationTokenSource.CreateLinkedTokenSource(ct); lease.CancelAfter(TimeSpan.FromMinutes(8));
            var state = await CurrentAuthClosedTemplate.PrepareAsync(files, binding, config.OperationId, config.ContainerId, source, admin, lease.Token).ConfigureAwait(false);
            await CurrentAuthClosedTemplate.InstallPolicyAsync(files, binding, state, admin, config.CaseId, lease.Token).ConfigureAwait(false);
            var capture = await CurrentAuthClosedTemplate.CaptureAsync(files, binding, state, source,
                config.CaseId is "host-unprobed-sdk" or "local-ordinary-trust", lease.Token).ConfigureAwait(false);
            string path = await CurrentAuthClosedConfiguration.WriteAsync(files, binding, capture, source, config.CaseId,
                config.CompletedComponents, config.PrecursorReviewPrivateKeyPath, config.TestAssemblyPath, lease.Token).ConfigureAwait(false);
            await output.WriteLineAsync(JsonSerializer.Serialize(new
            {
                kind = "current-auth-named-disposable-preparation-v1",
                path,
                sha256 = CurrentAuthRepairPermit.Hash(files.Read(path, sharedReader: true, maximumBytes: 32 * 1024 * 1024)),
                persistentAuthority = false,
                closedCasesExecuted = false
            })).ConfigureAwait(false);
            return 0;
        }
        catch (Exception failure) when (failure is MigrationExecutionException or MigrationConsoleException or IOException or
            UnauthorizedAccessException or JsonException or FormatException or InvalidOperationException or System.Security.Cryptography.CryptographicException or Npgsql.NpgsqlException)
        {
            await error.WriteLineAsync("current_auth_named_closed_preparation_failed").ConfigureAwait(false); return 1;
        }
    }
}

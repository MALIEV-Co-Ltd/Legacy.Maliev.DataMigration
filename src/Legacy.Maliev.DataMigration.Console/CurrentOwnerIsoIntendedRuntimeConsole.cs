using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

public static partial class MigrationConsole
{
    // New read-only metadata command only; never an execution/admission route.
    internal static async Task<int> RunOwnerIsoIntendedObservationAsync(string configPath, TextWriter output, TextWriter error, CancellationToken ct)
    {
        try
        {
            CurrentOwnerIsoCapacity.Require(admission: true);
            var config = await ReadProtectedJsonAsync<IsoIntendedObservationConfiguration>(configPath, "iso_intended_configuration_unprotected", ct).ConfigureAwait(false);
            var binding = await ReadProtectedJsonAsync<LocalExecutionBinding>(config.BindingPath, "iso_intended_binding_unprotected", ct).ConfigureAwait(false);
            using var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
            using var files = new CurrentAppOwnedRepairCustody(authority);
            var actual = DecodeOwnerIso<IsoIntendedObservationConfiguration>(files.Read(configPath, sharedReader: true, maximumBytes: 1_000_000));
            if (CurrentAppOwnedSnapshotSerialization.Sha256(actual) != CurrentAppOwnedSnapshotSerialization.Sha256(config)) { throw IsoIntendedRuntimeReader.Invalid(); }
            var observed = await IsoIntendedRuntimeObserver.ObserveAndRetainAsync(files, binding, config, ct).ConfigureAwait(false);
            byte[] retained = files.Read(config.OutputPath, sharedReader: true, maximumBytes: 8_000_000);
            if (CurrentAppOwnedSnapshotSerialization.Sha256(DecodeOwnerIso<IsoIntendedRuntimeObservation>(retained)) != CurrentAppOwnedSnapshotSerialization.Sha256(observed)) { throw IsoIntendedRuntimeReader.Invalid(); }
            await output.WriteLineAsync("Actual read-only intended target observations retained: " + CurrentAppOwnedRepairPermit.Hash(retained)).ConfigureAwait(false); return 0;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception failure) when (failure is MigrationExecutionException or IOException or UnauthorizedAccessException or JsonException or InvalidOperationException or FormatException or System.Security.Cryptography.CryptographicException)
        { await error.WriteLineAsync("iso_intended_runtime_observation_failed").ConfigureAwait(false); return 1; }
    }
}

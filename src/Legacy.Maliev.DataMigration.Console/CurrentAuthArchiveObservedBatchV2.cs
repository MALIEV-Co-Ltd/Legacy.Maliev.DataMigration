using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthArchiveObservedBatchV2(string Kind, Guid BatchId, string AudienceSha256,
    DateTimeOffset BeganAtUtc, DateTimeOffset CompletedAtUtc, IReadOnlyList<CurrentAuthArchiveGeneratedCaseRunV2> ActualCases,
    bool PhaseProofComplete);

public static partial class MigrationConsole
{
    // Fixed sequential producer only. This observation bundle is deliberately not a semantic proof or persistent authorization.
    internal static async Task<CurrentAuthArchiveObservedBatchV2> ObserveCurrentAuthArchiveAllCasesV2Async(
        CurrentAppOwnedRepairCustody parentFiles, WindowsLocalRunAuthority parentAuthority,
        CurrentAuthArchiveGeneratedCaseInputV2 input, CancellationToken ct)
    {
        parentFiles.Require(); parentAuthority.ValidateHeld();
        Guid batch = Guid.NewGuid(); DateTimeOffset began = DateTimeOffset.UtcNow;
        string prefix = Path.Combine(parentAuthority.Binding.ArtifactRootCanonicalPath, "archive-observed-batch-" + batch.ToString("N"));
        await parentFiles.WriteNewAsync(prefix + "-attempt.json", JsonSerializer.SerializeToUtf8Bytes(new
        { BatchId = batch, AudienceSha256 = input.Audience.Sha256, BeganAtUtc = began, PhaseProofComplete = false }), ct);
        var pins = new CurrentAuthArchivePins(input.Signing.Pins.ReviewKeyId, input.Signing.Pins.ReviewFingerprint,
            input.Signing.Pins.AuthorizationKeyId, input.Signing.Pins.AuthorizationFingerprint, input.Signing.Pins.ReceiptKeyId, input.Signing.Pins.ReceiptFingerprint);
        ReceiptAttestationTrustStore trust;
        var (Authority, Files) = CurrentAuthArchiveCaseCustodyV2.OpenQualified(input.QualifiedInputBinding, parentAuthority.Binding.ArtifactRootCanonicalPath);
        using (Authority)
        using (Files)
        {
            trust = new ReceiptAttestationTrustStore(input.Signing.TrustedKeys.Select(key => new TrustedAttestationKey(key.KeyId,
                Files.Read(key.SubjectPublicKeyInfoPath, sharedReader: true, maximumBytes: 65536))));
        }
        var actual = new List<CurrentAuthArchiveGeneratedCaseRunV2>();
        try
        {
            foreach (var selected in Enum.GetValues<CurrentAuthArchiveProofCaseV2>())
            {
                ct.ThrowIfCancellationRequested();
                var generated = await GenerateCurrentAuthArchiveCaseV2Async(parentFiles, parentAuthority, input, selected, ct);
                var completed = await RunCurrentAuthArchiveGeneratedCaseV2Async(generated, pins, trust, ct);
                actual.Add(completed);
                await parentFiles.WriteNewAsync(prefix + "-case-" + ((int)selected).ToString("D2", System.Globalization.CultureInfo.InvariantCulture) + ".json",
                    JsonSerializer.SerializeToUtf8Bytes(completed), ct);
            }
            var observed = new CurrentAuthArchiveObservedBatchV2("current-auth-archive-actual-eighteen-observations-v2", batch,
                input.Audience.Sha256, began, DateTimeOffset.UtcNow, actual.ToArray(), false);
            await parentFiles.WriteNewAsync(prefix + "-observations.json", JsonSerializer.SerializeToUtf8Bytes(observed), ct);
            return observed;
        }
        catch (Exception primary)
        {
            using var retention = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            try
            {
                await parentFiles.WriteNewAsync(prefix + "-failure.json", JsonSerializer.SerializeToUtf8Bytes(new
                {
                    BatchId = batch,
                    AudienceSha256 = input.Audience.Sha256,
                    BeganAtUtc = began,
                    FailedAtUtc = DateTimeOffset.UtcNow,
                    CompletedCases = actual.Select(x => x.Generated.Case).ToArray(),
                    FailureType = primary.GetType().Name,
                    PhaseProofComplete = false
                }), retention.Token);
            }
            catch (Exception evidence) { throw new AggregateException("The actual case batch and failure evidence retention failed.", primary, evidence); }
            throw;
        }
    }
}

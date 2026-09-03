using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

internal sealed class RecoveryAuthorityTestData : IDisposable
{
    private static readonly string[] KeyIds = ["backup", "authorization", "execution", "provenance", "final"];
    internal DateTimeOffset AdmittedAt = DateTimeOffset.Parse("2026-09-02T00:01:00Z", CultureInfo.InvariantCulture);
    internal readonly string[] PrivateKeyPems = [.. Enumerable.Range(0, 5).Select(_ => CreatePrivateKey())];
    internal readonly P256MigrationEvidenceSigner[] Signers;
    private RecoveryAuthorityTestData()
    {
        Signers = [.. KeyIds.Select((id, index) => new P256MigrationEvidenceSigner(id, PrivateKeyPems[index]))];
    }
    internal RecoveryAuthorityVerifier Verifier = null!;
    internal ReceiptAttestationTrustStore Trust = null!;
    internal InitialMigrationAdmissionPayload AdmissionPayload = null!;
    internal RestoredSourceObservation Source = null!;
    internal FreshTargetObservation Target = null!;
    internal FreshRunnerObservation Runner = null!;
    internal InitialMigrationAdmission Admission = null!;
    internal SourceContinuityAttestation Continuity = null!;
    internal RecoveryJournalBaseline Baseline = null!;
    internal ResumeAuthorizationReceipt Resume = null!;
    private TimeSpan _resumeDelay = TimeSpan.FromDays(2);
    internal DateTimeOffset Now => AdmittedAt.Add(_resumeDelay);
    internal LocalExecutionBinding Binding = new(1, "windows-host", "ntfs-volume", "C:\\ARTIFACTS\\RUN", "root-id", ".run.lock", "lock-id", 1);
    internal static RecoveryAuthorityRoles Roles => new("backup", "authorization", "execution", "provenance", "final");

    internal static async Task<RecoveryAuthorityTestData> CreateAsync(bool prepare = true, TimeSpan? resumeDelay = null, DateTimeOffset? admittedAt = null)
    {
        var data = new RecoveryAuthorityTestData();
        data.AdmittedAt = admittedAt ?? data.AdmittedAt;
        data._resumeDelay = resumeDelay ?? data._resumeDelay;
        using var source = new SourceObservationFixture();
        RestoredSourceObservation measured = await source.ObserveAsync();
        FreshSchemaPlan plan = new("2.0", data.AdmittedAt.AddMinutes(-10), new string('a', 40),
            DatabaseInventory.ActiveDatabases.Select(name => new DatabaseSchemaPlan(name, "1.0", Hash("source:" + name), Hash("target:" + name),
            [new("dbo", "Rows", "public", "Rows", ["ID"], ["ID"])
            {
                SourceColumnTypes = new Dictionary<string, string> { ["ID"] = "int" },
                SourceColumns = [new("ID", "int", Hash("ID:int"), null)],
                ColumnTypes = new Dictionary<string, string> { ["ID"] = "integer" },
                PrimaryKey = new("PK_Rows", ["ID"]),
            }])).ToArray());
        BackupArtifact?[] artifacts = DatabaseInventory.ActiveDatabases.Select(name => (BackupArtifact?)new BackupArtifact(name, "Full", $"Full_{name}_2026-09-01_220000.bak", 1, new string('d', 64), new string('d', 64))
        {
            CompletedAtUtc = data.AdmittedAt.AddHours(-1),
            GcsObject = $"test/{name}.bak",
            GcsGeneration = 1,
            GcsSha256 = new string('d', 64),
        }).ToArray();
        string manifest = Hash(string.Join('\n', artifacts.Select(item => item!).OrderBy(item => item.Database, StringComparer.Ordinal)
            .Select(item => string.Join('|', item.Database, item.BackupType, item.FileName, item.ByteLength, item.Sha256, item.ObservedSha256))));
        BackupReceipt backup = new("1.1", data.AdmittedAt.AddHours(-1), DatabaseInventory.InventorySha256, manifest, artifacts, "backup", null)
        { SourceObservedAtUtc = data.AdmittedAt.AddHours(-2) };
        Assert.True(ReceiptAttestation.TryCreatePayload(backup, out byte[] backupBytes));
        backup = backup with { AttestationSignature = Convert.ToBase64String(data.Signers[0].Sign(backupBytes)) };
        CloudNativePgTargetObservation target = new("maliev-legacy", "legacy-postgres-main", "target-uid", "23", 1, 1, "Cluster in healthy state", 1, 1, "p1", "p1", true, true, true, true)
        {
            ReconciliationEvidence = "observed-generation",
            ObservationReadCount = 1,
            StatusInstances = 1,
            SystemId = "system-1",
            InstanceNames = "p1",
            HealthyInstances = "p1",
            PvcCount = 1,
            HealthyPvcs = "pvc1",
            ReadyReason = "ClusterIsReady",
            ConsistentSystemIdReason = "Unique",
            ContinuousArchivingReason = "ContinuousArchivingSuccess",
            LastBackupSucceededReason = "LastBackupSucceeded",
        };
        ExecutionAuthorizationReceipt authorization = new("2.1", Guid.NewGuid(), data.AdmittedAt.AddMinutes(-5), data.AdmittedAt.AddMinutes(55),
            plan.SourceCommitSha, SchemaPlanCanonicalizer.ComputeSha256(plan), manifest, new string('b', 64), "1", DatabaseInventory.ActiveDatabases.ToArray(), "shadow-only", "authorization", null)
        { TargetObservation = target };
        Assert.True(ExecutionAuthorizationAttestation.TryCreatePayload(authorization, out byte[] authorizationBytes));
        authorization = authorization with { AttestationSignature = Convert.ToBase64String(data.Signers[1].Sign(authorizationBytes)) };
        VerifiedRestoreReceipt restore = source.Receipt with
        {
            AttestationKeyId = "provenance",
            BackupManifestSha256 = manifest,
            AttestationSignature = null,
            RestoredAtUtc = data.AdmittedAt.AddSeconds(-30)
        };
        Assert.True(VerifiedRestoreReceiptAttestation.TryCreatePayload(restore, out byte[] restoreBytes));
        restore = restore with { AttestationSignature = Convert.ToBase64String(data.Signers[3].Sign(restoreBytes)) };
        measured = measured with { ObservedAtUtc = data.AdmittedAt.AddSeconds(-10), State = measured.State with { VerifiedRestoreSha256 = Hash(restoreBytes), SchemaPlanSha256 = authorization.SchemaPlanSha256! } };
        data.AdmissionPayload = new(MigrationRunIdentity.FromRequest(new(backup, plan, authorization)), DatabaseInventory.InventorySha256,
            " \n" + JsonSerializer.Serialize(backup), JsonSerializer.Serialize(plan), JsonSerializer.Serialize(authorization), JsonSerializer.Serialize(restore),
            Hash(authorizationBytes), Hash(restoreBytes), measured, data.Binding, data.AdmittedAt, RecoveryAuthorityVerifier.ValidationPolicyVersion,
            GuardedRunnerPolicy.MaximumAuthorizationLifetime, RecoveryAuthorityVerifier.ValidationStatement);
        data.Trust = new(data.Signers.Select(signer => new TrustedAttestationKey(signer.KeyId, signer.ExportSubjectPublicKeyInfo())));
        data.Verifier = new(new(new(plan.SourceCommitSha, authorization.RunnerDigestSha256!), Roles, data.Trust));
        data.Source = measured with { ObservedAtUtc = data.Now };
        data.Target = new(data.Now, target);
        data.Runner = new(data.Now, authorization.RunnerDigestSha256!);
        if (prepare)
        {
            data.Admission = data.Verifier.PrepareAdmission(data.AdmissionPayload, data.Signers[2], data.AdmittedAt);
            data.Continuity = SourceContinuityAttestation.Sign(new(Guid.NewGuid(), RecoveryAuthorityVerifier.ComputeIdentitySha256(data.AdmissionPayload.Identity),
                data.Admission.ComputeSha256(), data.AdmissionPayload.VerifiedRestoreSha256, DatabaseInventory.InventorySha256, measured.ComputeSha256(), data.Source,
                data.Source.ComputeSha256(), data.Source.ComputeStableStateSha256(), data.AdmittedAt, data.Now,
                RecoveryAuthorityVerifier.ContinuityStatementVersion, RecoveryAuthorityVerifier.ContinuityStatement, data.Now, data.Now.AddHours(1)), data.Signers[3]);
            data.Baseline = new(data.AdmissionPayload.Identity, data.Admission.ComputeSha256(), "failed", "original-owner", 1, Guid.NewGuid(), null, "[]", [], []);
            data.Resume = data.PrepareResume();
        }
        return data;
    }

    internal ResumeAuthorizationReceipt PrepareResume()
    {
        return Verifier.PrepareResume(Admission, Continuity, Baseline, Source, Binding, Runner, Target,
        Guid.NewGuid(), Now, Now.AddHours(1), Signers[1], Now);
    }

    internal void ValidateResume(ResumeAuthorizationReceipt? resume = null)
    {
        Verifier.ValidateResume(Admission, Continuity, resume ?? Resume, Baseline,
            Source, Binding, Runner, Target, Now);
    }

    internal void ValidateContinuity(SourceContinuityAttestation continuity)
    {
        Verifier.ValidateContinuity(Admission, continuity, Source, Now);
    }

    internal static string Hash(string text)
    {
        return Hash(Encoding.UTF8.GetBytes(text));
    }

    internal static string Hash(byte[] bytes)
    {
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }

    private static string CreatePrivateKey()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return key.ExportPkcs8PrivateKeyPem();
    }
    public void Dispose() { foreach (P256MigrationEvidenceSigner signer in Signers) { signer.Dispose(); } }
}

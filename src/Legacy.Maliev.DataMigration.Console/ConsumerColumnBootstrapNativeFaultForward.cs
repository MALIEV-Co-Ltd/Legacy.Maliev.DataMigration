using System.Data;
using System.Text;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal static partial class ConsumerColumnBootstrapRehearsalProducer
{
    private static readonly IReadOnlyList<string> FaultForwardDatabases = Array.AsReadOnly(["Quotation"]);
    private static async Task<string> PrepareFaultForwardAsync(ConsumerColumnBootstrapProofFixture fixture,
        ConsumerColumnBootstrapNativeFaultControl control, ConsumerColumnBootstrapSourceCapture source, LocalExecutionBinding binding,
        ConsumerColumnBootstrapOperationalConfiguration original, IReadOnlyDictionary<string, string> current,
        List<(string Path, string Identity)> ownedSecrets, CancellationToken ct)
    {
        var old = ReadFault<ConsumerColumnBootstrapOperationalScope>(binding, original.ScopePath);
        Guid operation = Guid.NewGuid(); control.AuthorizeForward(operation);
        var contract = ConsumerColumnBootstrapContract.Create(source.Plan, source.Plan.SourceCommitSha, DateTimeOffset.UtcNow);
        var before = await CaptureFaultOperandAsync(fixture.OperatorDirectConnection, contract, "Quotation", after: false, ct).ConfigureAwait(false);
        ConsumerColumnBootstrapProviderObservation provider;
        await using (var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(fixture.OperatorDirectConnection) { Database = "Quotation", Pooling = false }.ConnectionString))
        {
            await connection.OpenAsync(ct).ConfigureAwait(false); await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
            await ExecuteAsync(connection, transaction, "SET TRANSACTION READ ONLY;", ct).ConfigureAwait(false);
            provider = await ConsumerColumnBootstrapProviderCapture.CaptureAsync(connection, transaction, ct).ConfigureAwait(false);
            await transaction.RollbackAsync(ct).ConfigureAwait(false);
        }
        var scope = old with
        {
            OperationId = operation,
            Mode = ConsumerColumnBootstrapOperationalMode.OwnedForwardRecoveryCharacterization,
            PendingDatabases = FaultForwardDatabases,
            PreviouslyCompletedDatabaseSha256 = new Dictionary<string, string>(StringComparer.Ordinal) { ["CustomerIdentity"] = current["CustomerIdentity"] },
            BeforeDatabaseSha256 = current,
            GlobalPreservationSha256 = ConsumerColumnBootstrapOperationalContract.FleetHash(current),
            NativePreimages = [ConsumerColumnBootstrapNativePreimage.Pin(before, provider, DateTimeOffset.UtcNow)],
        };
        using var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding); using var files = new CurrentAppOwnedRepairCustody(authority);
        string stem = "fault-forward-" + operation.ToString("N") + "-";
        using var review = new SignerMaterial("native-forward-review-"); using var authorization = new SignerMaterial("native-forward-authorization-"); using var receipt = new SignerMaterial("native-forward-receipt-");
        var keys = new Keys(review, authorization, receipt);
        var references = new List<DeltaTrustedKeyReference>();
        foreach (var key in keys.PublicKeys)
        { references.Add(new(key.KeyId, await Store(key.KeyId + ".spki", Encoding.UTF8.GetBytes(Convert.ToBase64String(key.SubjectPublicKeyInfo))).ConfigureAwait(false))); }
        string reviewPath = await Private("review-private.pem", review.Pem).ConfigureAwait(false);
        string authorizationPath = await Private("authorization-private.pem", authorization.Pem).ConfigureAwait(false);
        string receiptPath = await Private("receipt-private.pem", receipt.Pem).ConfigureAwait(false);
        var native = await Preparation("native").ConfigureAwait(false); var recovery = await Preparation("recovery").ConfigureAwait(false); var role = await Preparation("role").ConfigureAwait(false);
        scope = scope with { NativeCharacterizationSha256 = native.Sha256, RecoveryReviewSha256 = recovery.Sha256, RoleTransitionReviewSha256 = role.Sha256 };
        ConsumerColumnBootstrapOperationalContract.RequireScope(scope, source.Plan, DateTimeOffset.UtcNow);
        var baseline = new List<CurrentAppOwnedDatabaseSnapshot>();
        foreach (string database in current.Keys.Order(StringComparer.Ordinal))
        {
            await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(fixture.OperatorDirectConnection) { Database = database, Pooling = false }.ConnectionString);
            await connection.OpenAsync(ct).ConfigureAwait(false); await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
            await ExecuteAsync(connection, transaction, "SET TRANSACTION READ ONLY;", ct).ConfigureAwait(false);
            var snapshot = await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, transaction, ct).ConfigureAwait(false);
            if (snapshot.Sha256 != current[database]) { throw Invalid(); }
            baseline.Add(snapshot); await transaction.RollbackAsync(ct).ConfigureAwait(false);
        }
        var config = original with
        {
            ScopePath = await Store("scope.json", JsonSerializer.SerializeToUtf8Bytes(scope)).ConfigureAwait(false),
            ReviewPath = Path.Combine(binding.ArtifactRootCanonicalPath, stem + "review.json"),
            AuthorizationPath = Path.Combine(binding.ArtifactRootCanonicalPath, stem + "authorization.json"),
            SigningPinsPath = await Store("pins.json", JsonSerializer.SerializeToUtf8Bytes(keys.Pins)).ConfigureAwait(false),
            BeforeFleetPath = await Store("before-fleet.json", JsonSerializer.SerializeToUtf8Bytes(baseline)).ConfigureAwait(false),
            TrustedKeys = references,
            NativePreparation = native,
            RecoveryPreparation = recovery,
            RolePreparation = role,
            ReviewPrivateKeyPath = reviewPath,
            AuthorizationPrivateKeyPath = authorizationPath,
            ReceiptPrivateKeyPath = receiptPath,
        };
        return await Store("configuration.json", JsonSerializer.SerializeToUtf8Bytes(config)).ConfigureAwait(false);

        async Task<string> Store(string name, byte[] bytes)
        { string path = Path.Combine(binding.ArtifactRootCanonicalPath, stem + name); await files.WriteNewAsync(path, bytes, ct).ConfigureAwait(false); return path; }
        async Task<string> Private(string name, string pem)
        {
            string path = Path.Combine(binding.ArtifactRootCanonicalPath, stem + name); if (File.Exists(path)) { throw Invalid(); }
            int index = ownedSecrets.Count; ownedSecrets.Add((path, string.Empty));
            string identity = await ConsumerColumnBootstrapWindowsSecretCustody.CreateAsync(binding, files, path, Encoding.UTF8.GetBytes(pem), ct).ConfigureAwait(false);
            ownedSecrets[index] = (path, identity); return path;
        }
        async Task<CurrentAppOwnedRepairArtifact> Preparation(string kind)
        {
            var value = new ConsumerColumnBootstrapPreparationArtifact("consumer-column-bootstrap-" + kind + "-preparation-v1", operation,
                scope.LogicalSourcePlanSha256, scope.ContractSha256, scope.TargetObservationSha256, scope.RunBindingSha256, true, false,
                DateTimeOffset.UtcNow, scope.Maintenance.ExpiresAtUtc, scope.Maintenance.Role,
                new NpgsqlConnectionStringBuilder(ReadFaultSecretWithoutReacquiring(files, original.RejectedOrdinaryConnectionPath)).Username);
            byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value);
            return new(await Store(kind + ".json", bytes).ConfigureAwait(false), ConsumerColumnBootstrapOperationalContract.Hash(bytes));
        }
    }

    private static string ReadFaultSecretWithoutReacquiring(CurrentAppOwnedRepairCustody files, string path)
    {
        return Encoding.UTF8.GetString(files.Read(path, sharedReader: true, maximumBytes: 65536)).Trim();
    }

    private static void ClearForwardFaultSecrets(LocalExecutionBinding binding, List<(string Path, string Identity)> secrets)
    {
        ConsumerColumnBootstrapWindowsSecretCustody.RemoveDetached(binding, secrets, DateTimeOffset.UnixEpoch); secrets.Clear();
    }
}

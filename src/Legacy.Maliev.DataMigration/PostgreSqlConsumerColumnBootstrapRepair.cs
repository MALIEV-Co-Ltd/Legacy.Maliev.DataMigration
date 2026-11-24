using System.Data;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

/// <summary>Fixed transactional two-column family; admission owns rehearsal and target authorization.</summary>
internal static class PostgreSqlConsumerColumnBootstrapRepair
{
    internal static async Task<IReadOnlyList<ConsumerColumnBootstrapOperationalReceipt>> ExecuteAsync(FreshSchemaPlan source,
        IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> baseline, ConsumerColumnBootstrapOperationalPermit permit,
        P256MigrationEvidenceSigner signer, IReceiptAttestationTrustStore trust, CurrentAppOwnedRepairSigningPins pins, CancellationToken ct)
    {
        try { return await ExecuteCoreAsync(source, baseline, permit, signer, trust, pins, ct).ConfigureAwait(false); }
        finally { permit.Stop(); }
    }

    private static async Task<IReadOnlyList<ConsumerColumnBootstrapOperationalReceipt>> ExecuteCoreAsync(FreshSchemaPlan source,
        IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> baseline, ConsumerColumnBootstrapOperationalPermit permit,
        P256MigrationEvidenceSigner signer, IReceiptAttestationTrustStore trust, CurrentAppOwnedRepairSigningPins pins, CancellationToken ct)
    {
        baseline = baseline.Select(x => new CurrentAppOwnedDatabaseSnapshot(x.Database,
            Array.AsReadOnly(x.Catalog.ToArray()), Array.AsReadOnly(x.Relations.ToArray()), Array.AsReadOnly(x.Sequences.ToArray()))).ToArray();
        var scope = permit.Scope; var contract = ConsumerColumnBootstrapContract.Create(source, scope.SourceCommitSha, DateTimeOffset.UtcNow);
        if (signer.KeyId != pins.ReceiptKeyId || signer.PublicKeyFingerprintSha256 != pins.ReceiptFingerprint ||
            !trust.TryGetPublicKeyFingerprintSha256(signer.KeyId, out string fingerprint) || fingerprint != pins.ReceiptFingerprint ||
            baseline.Count != scope.BeforeDatabaseSha256.Count || baseline.Select(x => x.Database).Distinct(StringComparer.Ordinal).Count() != baseline.Count ||
            baseline.Any(x => !scope.BeforeDatabaseSha256.TryGetValue(x.Database, out string? hash) || x.Sha256 != hash))
        { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        var expected = scope.BeforeDatabaseSha256.ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal);
        var independentlyVerified = new Dictionary<string, string>(StringComparer.Ordinal);
        var receipts = new List<ConsumerColumnBootstrapOperationalReceipt>(); string previous = new('0', 64);
        try
        {
            await permit.StartAsync(ct).ConfigureAwait(false);
            foreach (string database in scope.PendingDatabases)
            {
                string beforeHash = expected[database]; string? afterHash = null;
                bool commitStarted = false, commitAcknowledged = false, rollbackAcknowledged = false;
                NpgsqlConnection? connection = null; NpgsqlTransaction? transaction = null;
                try
                {
                    await permit.RequireFleetAsync(expected, ct).ConfigureAwait(false);
                    var endpoint = new NpgsqlConnectionStringBuilder(permit.Environment.ConnectionString) { Database = database, Pooling = false };
                    if (endpoint.Host != "127.0.0.1" || endpoint.Port is < 1 or > 65535 || endpoint.Username != scope.Maintenance.Role ||
                        string.IsNullOrWhiteSpace(endpoint.Password) || !string.IsNullOrEmpty(endpoint.Options)) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
                    connection = new NpgsqlConnection(endpoint.ConnectionString); await connection.OpenAsync(ct).ConfigureAwait(false);
                    transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct).ConfigureAwait(false);
                    await CurrentAppOwnedRepairPreservation.LockAsync(connection, transaction, baseline.Single(x => x.Database == database), ct).ConfigureAwait(false);
                    await permit.Environment.RequirePolicyAsync(connection, transaction, scope, ct).ConfigureAwait(false);
                    await permit.RequireAsync(ct).ConfigureAwait(false);
                    var before = await ConsumerColumnBootstrapNativePreservation.CaptureAsync(connection, transaction, contract, database, false, ct).ConfigureAwait(false);
                    if (before.Native.Snapshot.Sha256 != beforeHash) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
                    var provider = await permit.Environment.ObserveProviderAsync(connection, transaction, ct).ConfigureAwait(false);
                    ConsumerColumnBootstrapNativePreimage.Require(scope.NativePreimages.Single(pin => pin.Database == database), before, provider, DateTimeOffset.UtcNow);
                    await permit.Environment.RetainNativeWitnessAsync(ConsumerColumnBootstrapNativePhase.LockedBefore, before, ct).ConfigureAwait(false);
                    await using (var ddl = new NpgsqlCommand(ConsumerColumnBootstrapContract.CandidateSql(database), connection, transaction) { CommandTimeout = 30 })
                    { _ = await ddl.ExecuteNonQueryAsync(ct).ConfigureAwait(false); }
                    var after = await ConsumerColumnBootstrapNativePreservation.CaptureAsync(connection, transaction, contract, database, true, ct).ConfigureAwait(false);
                    ConsumerColumnBootstrapNativePreservation.RequirePreserved(before, after, contract); afterHash = after.Native.Snapshot.Sha256;
                    await permit.Environment.RetainNativeWitnessAsync(ConsumerColumnBootstrapNativePhase.TransactionalAfter, after, ct).ConfigureAwait(false);
                    var prepared = SignReceipt(CurrentAppOwnedCommitClassification.Prepared);
                    await permit.Environment.RetainReceiptAsync(prepared, ct).ConfigureAwait(false);
                    previous = ConsumerColumnBootstrapOperationalContract.Hash(JsonSerializer.SerializeToUtf8Bytes(prepared));
                    await permit.RequireAsync(ct).ConfigureAwait(false);
                    await permit.Environment.RequirePolicyAsync(connection, transaction, scope, ct).ConfigureAwait(false);
                    commitStarted = true; await transaction.CommitAsync(ct).ConfigureAwait(false); commitAcknowledged = true;
                    await connection.CloseAsync().ConfigureAwait(false);
                    await using (var independent = new NpgsqlConnection(endpoint.ConnectionString))
                    {
                        await independent.OpenAsync(ct).ConfigureAwait(false);
                        await using var readback = await independent.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
                        await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY;", independent, readback)) { _ = await readOnly.ExecuteNonQueryAsync(ct).ConfigureAwait(false); }
                        await permit.Environment.RequirePolicyAsync(independent, readback, scope, ct).ConfigureAwait(false);
                        var observed = await ConsumerColumnBootstrapNativePreservation.CaptureAsync(independent, readback, contract, database, true, ct).ConfigureAwait(false);
                        ConsumerColumnBootstrapNativePreservation.RequirePreserved(before, observed, contract);
                        if (observed.Native.Snapshot.Sha256 != afterHash) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
                        independentlyVerified[database] = afterHash;
                        await permit.Environment.RetainNativeWitnessAsync(ConsumerColumnBootstrapNativePhase.IndependentReadback, observed, ct).ConfigureAwait(false);
                        await readback.RollbackAsync(ct).ConfigureAwait(false);
                    }
                    expected[database] = afterHash;
                    await permit.RequireFleetAsync(expected, ct).ConfigureAwait(false);
                    var terminal = SignReceipt(CurrentAppOwnedCommitClassification.CommittedAndReadback);
                    await permit.Environment.RetainReceiptAsync(terminal, ct).ConfigureAwait(false);
                    previous = ConsumerColumnBootstrapOperationalContract.Hash(JsonSerializer.SerializeToUtf8Bytes(terminal)); receipts.Add(terminal);
                }
                catch (Exception primary)
                {
                    permit.Stop(); using var failure = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                    if (!commitStarted && transaction is not null)
                    { try { await transaction.RollbackAsync(failure.Token).ConfigureAwait(false); rollbackAcknowledged = true; } catch (Exception rollback) when (rollback is NpgsqlException or OperationCanceledException) { rollbackAcknowledged = false; } }
                    try
                    {
                        var failed = SignReceipt(ClassifyFailure(commitStarted, commitAcknowledged, rollbackAcknowledged));
                        await permit.Environment.RetainReceiptAsync(failed, failure.Token).ConfigureAwait(false);
                        previous = ConsumerColumnBootstrapOperationalContract.Hash(JsonSerializer.SerializeToUtf8Bytes(failed));
                    }
                    catch (Exception evidence) { throw new AggregateException("Bootstrap failed and failure evidence could not be retained.", primary, evidence); }
                    throw;
                }
                finally
                {
                    if (transaction is not null) { await transaction.DisposeAsync().ConfigureAwait(false); }
                    if (connection is not null) { await connection.DisposeAsync().ConfigureAwait(false); }
                }

                ConsumerColumnBootstrapOperationalReceipt SignReceipt(CurrentAppOwnedCommitClassification classification)
                {
                    var unsigned = new ConsumerColumnBootstrapOperationalReceipt("consumer-column-bootstrap-receipt-v1", scope.OperationId, database, contract.ComputeSha256(),
                        permit.AuthorizationSha256, beforeHash, afterHash, previous, classification, DateTimeOffset.UtcNow, signer.KeyId, null);
                    return unsigned with { Signature = Convert.ToBase64String(signer.Sign(ReceiptPayload(unsigned))) };
                }
            }
            await permit.RequireFleetAsync(expected, ct).ConfigureAwait(false);
            await permit.RequireAsync(ct).ConfigureAwait(false);
            await permit.Environment.RetainRunReceiptAsync(SignRun(true), ct).ConfigureAwait(false);
            return receipts.AsReadOnly();
        }
        catch (Exception primary)
        {
            permit.Stop(); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            try { await permit.Environment.RetainRunReceiptAsync(SignRun(false), deadline.Token).ConfigureAwait(false); }
            catch (Exception evidence) { throw new AggregateException("Bootstrap run remained unfinished and its signed failure could not be retained.", primary, evidence); }
            throw;
        }
        finally { permit.Stop(); }

        ConsumerColumnBootstrapOperationalRunReceipt SignRun(bool completed)
        {
            var committed = receipts.ToDictionary(x => x.Database, x => x.AfterSha256!, StringComparer.Ordinal);
            var unsigned = new ConsumerColumnBootstrapOperationalRunReceipt("consumer-column-bootstrap-run-receipt-v1", scope.OperationId,
                permit.AuthorizationSha256, scope.LogicalSourcePlanSha256, scope.ContractSha256, previous, completed, committed,
                new Dictionary<string, string>(independentlyVerified, StringComparer.Ordinal),
                completed ? ConsumerColumnBootstrapOperationalContract.FleetHash(expected) : null, DateTimeOffset.UtcNow, signer.KeyId, null);
            return unsigned with { Signature = Convert.ToBase64String(signer.Sign(RunReceiptPayload(unsigned))) };
        }
    }

    internal static byte[] RunReceiptPayload(ConsumerColumnBootstrapOperationalRunReceipt receipt)
    {
        return [.. "Legacy.Maliev.ConsumerColumnBootstrap.RunReceipt.v1\0"u8, .. JsonSerializer.SerializeToUtf8Bytes(receipt with { Signature = null })];
    }

    internal static byte[] ReceiptPayload(ConsumerColumnBootstrapOperationalReceipt receipt)
    {
        return [.. "Legacy.Maliev.ConsumerColumnBootstrap.Receipt.v1\0"u8, .. JsonSerializer.SerializeToUtf8Bytes(receipt with { Signature = null })];
    }

    internal static CurrentAppOwnedCommitClassification ClassifyFailure(bool started, bool acknowledged, bool rollbackAcknowledged)
    {
        return started || acknowledged ? CurrentAppOwnedCommitClassification.Uncertain : rollbackAcknowledged
                ? CurrentAppOwnedCommitClassification.RolledBackBeforeCommit : CurrentAppOwnedCommitClassification.FailedBeforeCommit;
    }
}

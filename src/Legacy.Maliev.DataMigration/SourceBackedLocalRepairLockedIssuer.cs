using System.Data;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

/// <summary>
/// Trusted composition must maintain a maintenance window excluding new clients, global role
/// changes and catalog DDL for the complete call. Database locks cannot establish this promise.
/// </summary>
internal interface ISourceBackedLocalRepairMaintenance
{
    Task<ISourceBackedLocalRepairMaintenanceLease> AcquireAsync(HistoricalCurrentLocalObservation identity, CancellationToken cancellationToken);
}

internal interface ISourceBackedLocalRepairMaintenanceLease : IAsyncDisposable
{
    Task RequireStillQuiescentAsync(HistoricalCurrentLocalObservation identity, CancellationToken cancellationToken);
}

/// <summary>
/// Observes and signs complete LOCAL preimages while all exact-23 transaction locks are held.
/// Owns every connection and transaction; signed evidence grants no execution authority.
/// </summary>
internal sealed class SourceBackedLocalRepairLockedIssuer(
    string localConnectionString,
    Func<CancellationToken, Task<HistoricalCurrentLocalObservation>> observeTarget,
    ISourceBackedLocalRepairMaintenance maintenance,
    TimeProvider clock)
{
    internal static bool AuthorizesExecution => false;

    internal async Task<SourceBackedLocalRepairPreimageAttestation> IssueAsync(
        PairedCapturedDeltaPlans plans, Exact23DeltaReconciliationResult proof,
        FreshSchemaPlan schema, PairedLocalTransitionAuthorization authorization,
        IReadOnlyList<SourceBackedLocalRepairDatabasePreimage> expectedPreimages,
        IReceiptAttestationTrustStore trust, DateTimeOffset expiresAtUtc,
        P256MigrationEvidenceSigner signer, CancellationToken cancellationToken)
    {
        // Freeze caller-owned collections before any asynchronous boundary.
        plans = Snapshot(plans);
        proof = Snapshot(proof);
        schema = Snapshot(schema);
        authorization = Snapshot(authorization);
        SourceBackedLocalRepairDatabasePreimage[] expected = Snapshot(expectedPreimages.ToArray());
        ArgumentNullException.ThrowIfNull(maintenance);
        var endpoint = LocalPostgreSqlResourceAuthority.Connection(localConnectionString);
        if (!expected.Select(item => item?.Database).SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            !schema.Databases.Select(item => item.Database).SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal))
        {
            throw Invalid();
        }
        RequireAuthorization(plans, proof, schema, authorization, trust);
        HistoricalCurrentLocalObservation before = await observeTarget(cancellationToken).ConfigureAwait(false);
        if (before.SystemIdentifierSha256 != plans.Persistent.TargetAuthority!.SystemIdentifierSha256 ||
            before.DockerGeneration != plans.Persistent.TargetGeneration) { throw Invalid(); }
        await using ISourceBackedLocalRepairMaintenanceLease maintenanceLease =
            await maintenance.AcquireAsync(before, cancellationToken).ConfigureAwait(false);
        await maintenanceLease.RequireStillQuiescentAsync(before, cancellationToken).ConfigureAwait(false);
        var leases = new List<(NpgsqlConnection Connection, NpgsqlTransaction Transaction)>();
        SourceBackedLocalRepairPreimageAttestation? attestation = null;
        Exception? failure = null;
        try
        {
            var observed = new List<SourceBackedLocalRepairDatabasePreimage>();
            for (int ordinal = 0; ordinal < DatabaseInventory.ActiveDatabases.Count; ordinal++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                RequireAuthorization(plans, proof, schema, authorization, trust);
                endpoint.Database = DatabaseInventory.ActiveDatabases[ordinal];
                var connection = new NpgsqlConnection(endpoint.ConnectionString);
                NpgsqlTransaction transaction;
                try
                {
                    await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
                    // Independently verify the actual endpoint before BEGIN; this query must never
                    // create the Serializable snapshot used for lock/preimage inspection.
                    await RequireSystemAsync(connection, before, cancellationToken).ConfigureAwait(false);
                    transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
                }
                catch
                {
                    await connection.DisposeAsync().ConfigureAwait(false);
                    throw;
                }
                leases.Add((connection, transaction));
                // First transaction operation is the lock guard. No caller transaction is accepted.
                observed.Add(await SourceBackedLocalRepairLockSet.AcquireAndVerifyAsync(connection,
                    transaction, schema.Databases[ordinal], expected[ordinal], cancellationToken).ConfigureAwait(false));
            }
            HistoricalCurrentLocalObservation after = await observeTarget(cancellationToken).ConfigureAwait(false);
            if (before != after) { throw Invalid(); }
            await maintenanceLease.RequireStillQuiescentAsync(after, cancellationToken).ConfigureAwait(false);
            // All leases remain held through re-observation and authentication/signing. No claims,
            // fence, journal, pipeline or data changes are committed by this evidence issuer.
            cancellationToken.ThrowIfCancellationRequested();
            attestation = SourceBackedLocalRepairPreimageAttestationPolicy.Produce(plans, proof, schema,
                authorization, after, observed, trust, clock.GetUtcNow(), expiresAtUtc, signer);
        }
        catch (Exception exception) { failure = exception; }
        finally
        {
            // Cleanup ignores caller cancellation and attempts every lease even after a broken
            // endpoint. Connection disposal remains mandatory if explicit rollback fails.
            var failures = new List<Exception>();
            foreach (var (connection, transaction) in leases.AsEnumerable().Reverse())
            {
                try { await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false); }
                catch (Exception exception) { failures.Add(exception); }
                try { await transaction.DisposeAsync().ConfigureAwait(false); }
                catch (Exception exception) { failures.Add(exception); }
                try { await connection.DisposeAsync().ConfigureAwait(false); }
                catch (Exception exception) { failures.Add(exception); }
            }
            if (failures.Count != 0)
            {
                if (failure is not null) { failures.Insert(0, failure); }
                failure = new AggregateException("LOCAL preimage lease cleanup failed.", failures);
            }
        }
        if (failure is not null) { ExceptionDispatchInfo.Capture(failure).Throw(); }
        return attestation ?? throw Invalid();
    }

    private void RequireAuthorization(PairedCapturedDeltaPlans plans, Exact23DeltaReconciliationResult proof,
        FreshSchemaPlan schema, PairedLocalTransitionAuthorization authorization, IReceiptAttestationTrustStore trust)
    {
        PairedLocalTransitionAuthorizationPolicy.Verify(authorization, plans, proof, schema, trust,
            plans.Persistent.TargetAuthority!, plans.Persistent.TargetObservationSha256,
            plans.Persistent.QuotationTransitionSchemaSha256!, clock.GetUtcNow());
    }

    private static async Task RequireSystemAsync(NpgsqlConnection connection,
        HistoricalCurrentLocalObservation identity, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("SELECT system_identifier::text FROM pg_control_system();", connection);
        string value = (string)(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) ?? throw Invalid());
        string hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
        if (hash != identity.SystemIdentifierSha256) { throw Invalid(); }
    }

    private static T Snapshot<T>(T value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return JsonSerializer.Deserialize<T>(JsonSerializer.SerializeToUtf8Bytes(value)) ?? throw Invalid();
    }

    private static DeltaExecutionException Invalid()
    {
        return new("delta_source_repair_locked_issuer_invalid", "Locked LOCAL preimage issuance requires fresh exact-23 authenticated evidence, identity and trusted maintenance.");
    }
}

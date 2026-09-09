using System.Data;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

/// <summary>Records one atomic schema initialization of an already provisioned empty canonical database.</summary>
public sealed record CanonicalDatabaseBootstrapReceipt(
    string SchemaVersion,
    Guid AuthorizationId,
    string Database,
    string TargetSchemaSha256,
    string DatabaseResourceName,
    string DatabaseResourceUid,
    string DatabaseResourceGeneration,
    DeltaTargetAuthority TargetAuthority,
    DateTimeOffset CompletedAtUtc,
    string AttestationKeyId,
    string? AttestationSignature);

/// <summary>Creates deterministic domain-separated bytes for bootstrap execution receipts.</summary>
public static class CanonicalDatabaseBootstrapReceiptCanonicalizer
{
    private static ReadOnlySpan<byte> Domain => "legacy-maliev-canonical-database-bootstrap-receipt-v1.0\0"u8;

    /// <summary>Returns the unsigned receipt payload.</summary>
    public static byte[] CreatePayload(CanonicalDatabaseBootstrapReceipt receipt)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(receipt with { AttestationSignature = null });
        byte[] payload = new byte[Domain.Length + json.Length];
        Domain.CopyTo(payload);
        json.CopyTo(payload.AsSpan(Domain.Length));
        return payload;
    }
}

/// <summary>Atomically initializes one signed, empty, owner-only canonical PostgreSQL database.</summary>
public sealed class CanonicalDatabaseBootstrapExecutor
{
    private readonly CanonicalDatabaseBootstrapAuthorization _authorization;
    private readonly SignedCanonicalDatabaseBootstrapAuthorizationGate _authorizationGate;
    private readonly TimeProvider _timeProvider;
    private readonly P256MigrationEvidenceSigner _executionSigner;

    /// <summary>Creates an executor with distinct authorization and execution signing roles.</summary>
    public CanonicalDatabaseBootstrapExecutor(
        CanonicalDatabaseBootstrapAuthorization authorization,
        IReceiptAttestationTrustStore authorizationTrust,
        TimeProvider timeProvider,
        P256MigrationEvidenceSigner executionSigner)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        ArgumentNullException.ThrowIfNull(authorizationTrust);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(executionSigner);
        if (string.Equals(authorization.AttestationKeyId, executionSigner.KeyId, StringComparison.Ordinal))
        {
            throw new CanonicalDatabaseBootstrapException(
                "canonical_database_bootstrap_signing_roles_invalid",
                "Bootstrap authorization and execution receipts require distinct signing roles.");
        }

        _authorization = authorization;
        _authorizationGate = new(authorization, authorizationTrust, timeProvider);
        _timeProvider = timeProvider;
        _executionSigner = executionSigner;
    }

    /// <summary>Applies the exact authorized schema only when the connected database is empty and owner-only.</summary>
    public async Task<CanonicalDatabaseBootstrapReceipt> ExecuteAsync(
        CanonicalDatabaseBootstrapRequest request,
        string targetConnectionString,
        string expectedOwnerRole,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(targetConnectionString);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedOwnerRole);
        await _authorizationGate.ValidateAsync(request, cancellationToken).ConfigureAwait(false);

        var settings = new NpgsqlConnectionStringBuilder(targetConnectionString);
        if (!string.Equals(settings.Database, request.Schema.Database, StringComparison.Ordinal))
        {
            throw BoundaryInvalid();
        }

        await using var connection = new NpgsqlConnection(settings.ConnectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
            IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
        bool schemaMutationStarted = false;

        try
        {
            await ValidateBoundaryAsync(
                connection, transaction, request, expectedOwnerRole, cancellationToken).ConfigureAwait(false);
            await AcquireLockAsync(connection, transaction, request.Schema.Database, cancellationToken).ConfigureAwait(false);

            bool empty;
            try
            {
                empty = await PostgreSqlShadowRecoveryObjects.InspectAsync(
                    connection, transaction, request.Schema, cancellationToken).ConfigureAwait(false);
            }
            catch (MigrationExecutionException exception) when (
                string.Equals(exception.Code, "shadow_recovery_objects_invalid", StringComparison.Ordinal))
            {
                throw TargetNotEmpty();
            }

            if (!empty)
            {
                throw TargetNotEmpty();
            }

            var schemaWriter = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
            schemaMutationStarted = true;
            await schemaWriter.ApplySchemaAsync(request.Schema, cancellationToken).ConfigureAwait(false);
            await schemaWriter.FinalizeSchemaAsync(request.Schema, cancellationToken).ConfigureAwait(false);
            string observedSchema = await schemaWriter.InspectSchemaAsync(request.Schema, cancellationToken).ConfigureAwait(false);
            if (!CanonicalDatabaseBootstrapAuthorizationProducer.Fixed(
                request.Schema.TargetSchemaSha256, observedSchema))
            {
                throw new CanonicalDatabaseBootstrapException(
                    "canonical_database_bootstrap_schema_mismatch",
                    "The initialized database schema does not match the signed target schema.");
            }

            foreach (TableCopyPlan table in request.Schema.Tables)
            {
                TableReconciliationEvidence evidence = await schemaWriter.InspectTableAsync(table, cancellationToken)
                    .ConfigureAwait(false);
                if (evidence.RowCount != 0)
                {
                    throw TargetNotEmpty();
                }
            }

            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            try
            {
                await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch (InvalidOperationException)
            {
                // A failed transaction can already be rolled back by PostgreSQL/Npgsql.
            }
            if (exception is PostgresException)
            {
                throw new CanonicalDatabaseBootstrapException(
                    schemaMutationStarted
                        ? "canonical_database_bootstrap_schema_apply_failed"
                        : "canonical_database_bootstrap_boundary_invalid",
                    schemaMutationStarted
                        ? "PostgreSQL rejected the authorized schema and the complete bootstrap transaction was rolled back."
                        : "PostgreSQL could not prove the signed owner-only target boundary.",
                    exception);
            }
            throw;
        }

        var unsigned = new CanonicalDatabaseBootstrapReceipt(
            "1.0",
            _authorization.AuthorizationId,
            request.Schema.Database,
            request.Schema.TargetSchemaSha256,
            request.DatabaseResourceName,
            request.DatabaseResourceUid,
            request.DatabaseResourceGeneration,
            request.TargetAuthority,
            _timeProvider.GetUtcNow(),
            _executionSigner.KeyId,
            null);
        return unsigned with
        {
            AttestationSignature = Convert.ToBase64String(_executionSigner.Sign(
                CanonicalDatabaseBootstrapReceiptCanonicalizer.CreatePayload(unsigned))),
        };
    }

    private static async Task ValidateBoundaryAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        CanonicalDatabaseBootstrapRequest request,
        string expectedOwnerRole,
        CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT current_database(), pg_get_userbyid(d.datdba),
                EXISTS (
                    SELECT 1
                    FROM aclexplode(COALESCE(d.datacl, acldefault('d', d.datdba))) AS acl
                    WHERE acl.grantee = 0 AND acl.privilege_type = 'CONNECT')
            FROM pg_database AS d
            WHERE d.datname = current_database();
            """;
        await using (var command = new NpgsqlCommand(sql, connection, transaction))
        await using (NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
        {
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ||
                !string.Equals(reader.GetString(0), request.Schema.Database, StringComparison.Ordinal) ||
                !string.Equals(reader.GetString(1), expectedOwnerRole, StringComparison.Ordinal) ||
                reader.GetBoolean(2))
            {
                throw BoundaryInvalid();
            }
        }

        await using var identity = new NpgsqlCommand(
            "SELECT system_identifier::text FROM pg_control_system();", connection, transaction);
        string? systemIdentifier = (string?)await identity.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        string observedHash = Convert.ToHexString(SHA256.HashData(
            Encoding.ASCII.GetBytes(systemIdentifier ?? string.Empty))).ToLowerInvariant();
        if (!CanonicalDatabaseBootstrapAuthorizationProducer.Fixed(
            request.TargetAuthority.SystemIdentifierSha256, observedHash))
        {
            throw new CanonicalDatabaseBootstrapException(
                "canonical_database_bootstrap_system_identifier_invalid",
                "The connected PostgreSQL system identifier does not match the signed target cluster.");
        }
    }

    private static async Task AcquireLockAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        string database,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0));", connection, transaction);
        _ = command.Parameters.AddWithValue($"legacy-maliev-canonical-bootstrap:{database}");
        _ = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
    }

    private static CanonicalDatabaseBootstrapException BoundaryInvalid()
    {
        return new(
            "canonical_database_bootstrap_boundary_invalid",
            "The connected PostgreSQL database does not match the signed owner-only target boundary.");
    }

    private static CanonicalDatabaseBootstrapException TargetNotEmpty()
    {
        return new(
            "canonical_database_bootstrap_target_not_empty",
            "Canonical database bootstrap requires a database with no pre-existing user objects or rows.");
    }
}

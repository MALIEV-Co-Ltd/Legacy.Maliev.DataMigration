using System.Data;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

public sealed record QuotationOutcomeAdoptionResult(
    int InsertedCount,
    int ReplayedCount,
    QuotationOutcomeInventoryContract VerifiedCanonical);

public static class QuotationOutcomeSignedAdoptionGate
{
    public static void VerifyAndValidate(
        QuotationOutcomeAdoptionContract contract,
        QuotationAdoptionObservation observation,
        IReceiptAttestationTrustStore trustStore)
    {
        if (!QuotationOutcomeAdoptionAttestation.Verify(contract, trustStore))
        {
            throw new QuotationOutcomeAdoptionException(
                "quotation_adoption_attestation_invalid",
                "The quotation adoption contract is unsigned, tampered, or signed by an untrusted key.");
        }

        QuotationOutcomeAdoptionValidator.Validate(contract, observation);
    }
}

public sealed class PostgreSqlQuotationOutcomeAdopter
{
    public static async Task<QuotationOutcomeAdoptionResult> AdoptSignedAsync(
        NpgsqlConnection connection,
        QuotationOutcomeAdoptionContract contract,
        IReadOnlyCollection<QuotationOutcomeSourceRow> sourceRows,
        long sourceNextIdentity,
        QuotationAdoptionObservation observation,
        IReceiptAttestationTrustStore trustStore,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(contract);
        ArgumentNullException.ThrowIfNull(sourceRows);
        ArgumentNullException.ThrowIfNull(observation);
        ArgumentNullException.ThrowIfNull(trustStore);

        if (!QuotationOutcomeAdoptionAttestation.Verify(contract, trustStore))
        {
            throw new QuotationOutcomeAdoptionException(
                "quotation_adoption_attestation_invalid",
                "The quotation adoption contract is unsigned, tampered, or signed by an untrusted key.");
        }

        var actualSource = new QuotationOutcomeInventoryContract(
            sourceRows.Count,
            QuotationOutcomeTransformPlanner.ComputeContentSha256(sourceRows),
            sourceNextIdentity);
        if (contract.Data is null || actualSource != contract.Data.Source)
        {
            throw new QuotationOutcomeAdoptionException(
                "quotation_adoption_source_drift",
                "The observed source rows or identity sequence do not match the signed adoption contract.");
        }

        QuotationOutcomeSignedAdoptionGate.VerifyAndValidate(
            contract,
            observation with { VerifiedCanonical = contract.Data.ExpectedCanonical },
            trustStore);
        QuotationOutcomeAdoptionResult result = await AdoptAsync(
            connection, contract.Data, sourceRows, sourceNextIdentity, cancellationToken).ConfigureAwait(false);
        return result;
    }

    private static async Task<QuotationOutcomeAdoptionResult> AdoptAsync(
        NpgsqlConnection connection,
        QuotationOutcomeDataContract signedData,
        IReadOnlyCollection<QuotationOutcomeSourceRow> sourceRows,
        long sourceNextIdentity,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);
        if (connection.State != ConnectionState.Open)
        {
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        }

        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
            IsolationLevel.ReadCommitted, cancellationToken).ConfigureAwait(false);
        await using (var lockCommand = new NpgsqlCommand("SELECT pg_advisory_xact_lock(4861294633252357964);", connection, transaction))
        {
            _ = await lockCommand.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        }

        QuotationAcceptedOutcomeImportRow[] existing = await ReadCanonicalAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
        QuotationOutcomeImportPlan plan = QuotationOutcomeTransformPlanner.Create(sourceRows, existing, sourceNextIdentity);
        long[] actualInsertIds = plan.Inserts.Select(row => row.ID).Order().ToArray();
        long[] actualReplayIds = plan.AlreadyApplied.Select(row => row.ID).Order().ToArray();
        if (!actualInsertIds.SequenceEqual(signedData.InsertIds.Order()) ||
            !actualReplayIds.SequenceEqual(signedData.ReplayIds.Order()))
        {
            throw new QuotationOutcomeAdoptionException(
                "quotation_adoption_partition_drift",
                "The observed insert and replay partitions do not match the signed adoption contract.");
        }

        foreach (QuotationAcceptedOutcomeImportRow row in plan.Inserts)
        {
            const string insertSql = """
                INSERT INTO "QuotationAcceptedOutcome"
                    ("ID", "EventKey", "QuotationID", "SourceRequestID", "SourceJourneyID", "AcceptedUtc",
                     "AcceptedUtcSubMicrosecondTicks", "AcceptanceOrigin")
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8);
                """;
            await using var insert = new NpgsqlCommand(insertSql, connection, transaction);
            _ = insert.Parameters.AddWithValue(row.ID);
            _ = insert.Parameters.AddWithValue(row.EventKey);
            _ = insert.Parameters.AddWithValue(row.QuotationID);
            _ = insert.Parameters.AddWithValue((object?)row.SourceRequestID ?? DBNull.Value);
            _ = insert.Parameters.AddWithValue((object?)row.SourceJourneyID ?? DBNull.Value);
            _ = insert.Parameters.AddWithValue(row.AcceptedUtc.AddTicks(-(row.AcceptedUtc.Ticks % 10)));
            _ = insert.Parameters.AddWithValue((short)(row.AcceptedUtc.Ticks % 10));
            _ = insert.Parameters.AddWithValue(row.AcceptanceOrigin);
            _ = await insert.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }

        QuotationAcceptedOutcomeImportRow[] verifiedRows = await ReadCanonicalAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
        QuotationOutcomeSourceRow[] reconstructed = verifiedRows.Select(row => new QuotationOutcomeSourceRow(
            row.ID, row.EventKey, row.QuotationID, row.SourceRequestID, row.SourceJourneyID,
            row.AcceptedUtc, row.AcceptanceOrigin)).ToArray();
        long verifiedRowCount = reconstructed.Length;
        string verifiedContentSha256 = QuotationOutcomeTransformPlanner.ComputeContentSha256(reconstructed);
        if (verifiedRowCount != signedData.ExpectedCanonical.RowCount ||
            !string.Equals(verifiedContentSha256, signedData.ExpectedCanonical.ContentSha256, StringComparison.Ordinal) ||
            sourceNextIdentity != signedData.ExpectedCanonical.NextIdentity)
        {
            throw new QuotationOutcomeAdoptionException(
                "quotation_adoption_target_drift",
                "The canonical rows or identity sequence do not match the signed adoption contract.");
        }

        const string sequenceSql = "SELECT setval(pg_get_serial_sequence('\"QuotationAcceptedOutcome\"', 'ID'), $1, $2);";
        await using (var sequence = new NpgsqlCommand(sequenceSql, connection, transaction))
        {
            _ = sequence.Parameters.AddWithValue(sourceNextIdentity == 1 ? 1 : sourceNextIdentity - 1);
            _ = sequence.Parameters.AddWithValue(sourceNextIdentity != 1);
            _ = await sequence.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        }

        var verified = new QuotationOutcomeInventoryContract(
            verifiedRowCount,
            verifiedContentSha256,
            await ReadNextIdentityAsync(connection, transaction, cancellationToken).ConfigureAwait(false));
        if (verified != signedData.ExpectedCanonical)
        {
            throw new QuotationOutcomeAdoptionException(
                "quotation_adoption_target_drift",
                "The canonical identity sequence does not match the signed adoption contract.");
        }

        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return new(plan.Inserts.Count, plan.AlreadyApplied.Count, verified);
    }

    public static async Task<string> ComputeCanonicalSchemaSha256Async(
        NpgsqlConnection connection,
        CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT string_agg(fact, E'\n' ORDER BY fact) FROM (
              SELECT 'column|' || a.attnum || '|' || a.attname || '|' || format_type(a.atttypid,a.atttypmod) || '|' || a.attnotnull || '|' || coalesce(pg_get_expr(d.adbin,d.adrelid),'') AS fact
              FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
              LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
              WHERE n.nspname='public' AND c.relname='QuotationAcceptedOutcome' AND a.attnum>0 AND NOT a.attisdropped
              UNION ALL
              SELECT 'index|' || indexname || '|' || indexdef FROM pg_indexes WHERE schemaname='public' AND tablename='QuotationAcceptedOutcome'
            ) facts;
            """;
        await using var command = new NpgsqlCommand(sql, connection);
        string facts = (string)(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) ?? string.Empty);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(facts))).ToLowerInvariant();
    }

    private static async Task<QuotationAcceptedOutcomeImportRow[]> ReadCanonicalAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT "ID", "EventKey", "QuotationID", "SourceRequestID", "SourceJourneyID", "AcceptedUtc",
                   "AcceptedUtcSubMicrosecondTicks", "AcceptanceOrigin"
            FROM "QuotationAcceptedOutcome" ORDER BY "ID";
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        List<QuotationAcceptedOutcomeImportRow> rows = [];
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            DateTime accepted = reader.GetDateTime(5).AddTicks(reader.GetInt16(6));
            rows.Add(new(reader.GetInt64(0), reader.GetString(1), reader.GetInt32(2),
                reader.IsDBNull(3) ? null : reader.GetInt32(3), reader.IsDBNull(4) ? null : reader.GetGuid(4),
                accepted, reader.GetString(7)));
        }

        return rows.ToArray();
    }

    private static async Task<long> ReadNextIdentityAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        CancellationToken cancellationToken)
    {
        const string sql = "SELECT CASE WHEN is_called THEN last_value + 1 ELSE last_value END FROM \"QuotationAcceptedOutcome_ID_seq\";";
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        return Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), CultureInfo.InvariantCulture);
    }
}

using System.Data;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal static class DualTargetNativeProofFence
{
    // Only the source database's own fence row is rebound on the freshly verified disposable.
    internal static async Task<DualTargetNativeProofRows> RebindAsync(DualTargetNativeProofClone clone,
        DatabaseSchemaPlan database, string fullSchemaSha256, DualTargetCapturedTargetObservation observation, CancellationToken ct)
    {
        await clone.RequireOwnedAsync(ct).ConfigureAwait(false);
        var settings = new NpgsqlConnectionStringBuilder(clone.Connection) { Database = database.Database };
        await using var connection = new NpgsqlConnection(settings.ConnectionString); await connection.OpenAsync(ct).ConfigureAwait(false);
        await using var tx = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct).ConfigureAwait(false);
        await DualTargetNativeProofLogicalCapture.ExecuteAsync(connection, tx,
            "LOCK TABLE legacy_migration_internal.delta_fence IN ACCESS EXCLUSIVE MODE;", ct).ConfigureAwait(false);
        await using (var shape = new NpgsqlCommand("""
            SELECT jsonb_agg(attname ORDER BY attnum)::text FROM pg_attribute
            WHERE attrelid='legacy_migration_internal.delta_fence'::regclass AND attnum>0 AND NOT attisdropped;
            """, connection, tx))
        {
            string[] names = JsonSerializer.Deserialize<string[]>((string)(await shape.ExecuteScalarAsync(ct).ConfigureAwait(false) ?? throw DualTargetNativeProofPreimage.Invalid()))!;
            string[] expected = ["database_name", "schema_plan_sha256", "target_schema_sha256", "target_generation", "target_observation_sha256"];
            if (!names.SequenceEqual(expected, StringComparer.Ordinal)) { throw DualTargetNativeProofPreimage.Invalid(); }
        }
        string original;
        await using (var read = new NpgsqlCommand("SELECT to_jsonb(f)::text FROM legacy_migration_internal.delta_fence f WHERE database_name=$1 FOR UPDATE;", connection, tx))
        {
            _ = read.Parameters.AddWithValue(database.Database);
            await using var reader = await read.ExecuteReaderAsync(ct).ConfigureAwait(false);
            if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { throw DualTargetNativeProofPreimage.Invalid(); }
            original = reader.GetString(0);
            if (await reader.ReadAsync(ct).ConfigureAwait(false)) { throw DualTargetNativeProofPreimage.Invalid(); }
        }
        // Evaluate the complete expected multiset in PostgreSQL's own jsonb formatting, including all other rows.
        string expectedQuery = """
            SELECT encode(sha256(convert_to((CASE WHEN f.database_name=$1 THEN to_jsonb(f)||jsonb_build_object(
              'schema_plan_sha256',$2::text,'target_schema_sha256',$3::text,'target_generation',$4::text,'target_observation_sha256',$5::text)
              ELSE to_jsonb(f) END)::text,'UTF8')),'hex') AS h FROM legacy_migration_internal.delta_fence f ORDER BY h;
            """;
        DualTargetNativeProofRows expectedRows;
        await using (var expected = new NpgsqlCommand(expectedQuery, connection, tx))
        {
            Bind(expected, database, fullSchemaSha256, observation);
            using var hash = System.Security.Cryptography.IncrementalHash.CreateHash(System.Security.Cryptography.HashAlgorithmName.SHA256); long count = 0;
            await using var reader = await expected.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await reader.ReadAsync(ct).ConfigureAwait(false)) { hash.AppendData(System.Text.Encoding.ASCII.GetBytes(reader.GetString(0))); count++; }
            expectedRows = new(count, Convert.ToHexStringLower(hash.GetHashAndReset()));
        }
        await using (var write = new NpgsqlCommand("""
            UPDATE legacy_migration_internal.delta_fence f SET schema_plan_sha256=$2,target_schema_sha256=$3,
              target_generation=$4,target_observation_sha256=$5 WHERE database_name=$1 AND to_jsonb(f)=$6::jsonb;
            """, connection, tx))
        {
            Bind(write, database, fullSchemaSha256, observation); _ = write.Parameters.AddWithValue(original);
            if (await write.ExecuteNonQueryAsync(ct).ConfigureAwait(false) != 1) { throw DualTargetNativeProofPreimage.Invalid(); }
        }
        DualTargetNativeProofRows actual = await DualTargetNativeProofLogicalCapture.RowsAsync(connection, tx,
            "SELECT encode(sha256(convert_to(to_jsonb(f)::text,'UTF8')),'hex') AS h FROM legacy_migration_internal.delta_fence f ORDER BY h;", ct).ConfigureAwait(false);
        if (actual != expectedRows) { throw DualTargetNativeProofPreimage.Invalid(); }
        await tx.CommitAsync(ct).ConfigureAwait(false); return expectedRows;
    }

    private static void Bind(NpgsqlCommand command, DatabaseSchemaPlan database, string fullSchemaSha256, DualTargetCapturedTargetObservation observation)
    {
        _ = command.Parameters.AddWithValue(database.Database); _ = command.Parameters.AddWithValue(fullSchemaSha256);
        _ = command.Parameters.AddWithValue(database.TargetSchemaSha256); _ = command.Parameters.AddWithValue(observation.Generation);
        _ = command.Parameters.AddWithValue(observation.Sha256);
    }
}

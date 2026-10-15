using System.Data;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record Production181RawCapture(JsonElement Engine, CurrentCustomerSequenceObservation Customer);
internal sealed record Production181RunCapture(Guid RunId, DateTimeOffset ObservedAtUtc, Production181RawCapture Actual);
internal static class Production181RawCaptureReader
{
    // Exact fresh endpoint must already be independently owned/pinned by the disposable fixture.
    // No caller-supplied authority is accepted and no SQL writes or allocation calls occur here.
    internal static async Task<Production181RawCapture> CaptureAsync(NpgsqlConnection connection, CancellationToken ct)
    {
        CurrentCustomerSequenceCapacity.Require(admission: false);
        if (connection.Database != "Customer") { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
        await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, tx))
        { _ = await readOnly.ExecuteNonQueryAsync(ct).ConfigureAwait(false); }
        const string sql = """
            SELECT jsonb_build_object('serverVersionNum',current_setting('server_version_num')::integer,
              'version',version(),'encoding',current_setting('server_encoding'),'autovacuum',current_setting('autovacuum'),
              'checksums',current_setting('data_checksums'),'dataDirectory',current_setting('data_directory'),
              'primary',NOT pg_is_in_recovery(),'controlSystem',to_jsonb(pg_control_system()),'controlInit',to_jsonb(pg_control_init()),
              'database',to_jsonb(d),'collations',(SELECT jsonb_agg(to_jsonb(c)||jsonb_build_object('actualVersion',pg_collation_actual_version(c.oid)) ORDER BY c.oid)
                FROM pg_collation c WHERE c.oid IN ('public.legacy_ci_as'::regcollation,'pg_catalog."C"'::regcollation)))::text
            FROM pg_database d WHERE datname=current_database();
            """;
        await using var command = new NpgsqlCommand(sql, connection, tx) { CommandTimeout = 30 };
        string raw = (string?)await command.ExecuteScalarAsync(ct).ConfigureAwait(false) ?? throw CurrentCustomerSequenceRepairPermit.Invalid();
        using var json = JsonDocument.Parse(raw); JsonElement engine = json.RootElement.Clone(); RequireEngine(engine);
        CurrentCustomerSequenceCapacity.Require(admission: false);
        var observation = await CurrentCustomerSequenceNativeObservation.CaptureAsync(connection, tx, ct).ConfigureAwait(false);
        await tx.RollbackAsync(ct).ConfigureAwait(false);
        return new(engine, observation);
    }
    internal static void RequireEngine(JsonElement engine)
    {
        var database = engine.GetProperty("database");
        if (engine.GetProperty("serverVersionNum").GetInt32() != Production181EngineContract.ServerVersion ||
            !engine.GetProperty("version").GetString()!.StartsWith("PostgreSQL 18.1 (Debian 18.1-1.pgdg12+2)", StringComparison.Ordinal) ||
            engine.GetProperty("encoding").GetString() != "UTF8" || engine.GetProperty("autovacuum").GetString() != "off" ||
            engine.GetProperty("checksums").GetString() != "on" || engine.GetProperty("dataDirectory").GetString() != Production181EngineContract.Data ||
            !engine.GetProperty("primary").GetBoolean() || engine.GetProperty("controlInit").GetProperty("data_page_checksum_version").GetInt32() != 1 ||
            database.GetProperty("datname").GetString() != "Customer" || database.GetProperty("datcollate").GetString() != "C" || database.GetProperty("datctype").GetString() != "C" || database.GetProperty("datlocprovider").GetString() != "c")
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        var ci = engine.GetProperty("collations").EnumerateArray().Single(x => x.GetProperty("collname").GetString() == "legacy_ci_as");
        if (ci.GetProperty("collprovider").GetString() != "i" || ci.GetProperty("collisdeterministic").GetBoolean() ||
            ci.GetProperty("colllocale").GetString() != "und-u-ks-level2" || ci.GetProperty("collversion").GetString() != "153.120" || ci.GetProperty("actualVersion").GetString() != "153.120")
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
    }
}

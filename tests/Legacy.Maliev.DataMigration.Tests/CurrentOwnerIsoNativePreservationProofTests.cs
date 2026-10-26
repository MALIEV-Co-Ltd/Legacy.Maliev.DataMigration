using System.Data;
using Npgsql;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class CurrentOwnerIsoNativeProofGroup
{
    public const string Name = "Current owner ISO disposable literal preservation";
}

/// <summary>Disposable candidate feasibility only; this fixture is not a runtime repair or authority.</summary>
public sealed partial class CurrentOwnerIsoNativePreservationTests
{
    private static readonly string[] WidthFixtureDatabases = ["iso_country_fixture", "iso_material_fixture"];
    [WindowsLocalRunFact]
    public Task Width_expansion_preserves_native_bytes_nulls_outside_catalogs_rows_and_sequence_and_rollback()
    {
        return RunOwnedAsync("width", null, async (admin, token) =>
    {
        // Different databases and values: retained Material evidence never borrows Country row provenance.
        foreach (string database in WidthFixtureDatabases)
        {
            await CreateDatabaseAsync(admin, database, token);
            await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(admin)
            { Database = database, Pooling = false }.ConnectionString);
            await connection.OpenAsync(token);
            Assert.Equal("off", await ScalarAsync<string>(connection, "SHOW autovacuum;", token));
            await BootstrapAsync(connection, database, token);
            string rows = await RowsAsync(connection, after: false, token);
            string outside = await OutsideAsync(connection, token);
            IsoDefinitionRecorder.Projection(database, "before", rows, outside);
            Assert.True(await ScalarAsync<bool>(connection, """
                SELECT bool_and(("ISO2" IS NULL OR char_length(convert_from(bpcharsend("ISO2"),'UTF8'))=2)
                    AND ("ISO3" IS NULL OR char_length(convert_from(bpcharsend("ISO3"),'UTF8'))=3))
                    AND bool_or(octet_length(bpcharsend("ISO2")) > 2)
                    AND bool_or(bpcharsend("ISO2") <> convert_to("ISO2"::text,'UTF8'))
                FROM public."Country";
                """, token));
            await using (NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, token))
            {
                await CandidateAsync(connection, transaction, token);
                Assert.Equal(rows, await RowsAsync(connection, after: true, token, transaction));
                Assert.Equal(outside, await OutsideAsync(connection, token, transaction));
                IsoDefinitionRecorder.Projection(database, "candidate", await RowsAsync(connection, true, token, transaction), await OutsideAsync(connection, token, transaction));
                await transaction.RollbackAsync(token);
            }
            Assert.Equal(rows, await RowsAsync(connection, after: false, token));
            Assert.Equal(outside, await OutsideAsync(connection, token));
            IsoDefinitionRecorder.Projection(database, "rollback", await RowsAsync(connection, false, token), await OutsideAsync(connection, token));
            await using (NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, token))
            {
                await CandidateAsync(connection, transaction, token);
                Assert.Equal(rows, await RowsAsync(connection, after: true, token, transaction));
                Assert.Equal(outside, await OutsideAsync(connection, token, transaction));
                IsoDefinitionRecorder.Projection(database, "commit-candidate", await RowsAsync(connection, true, token, transaction), await OutsideAsync(connection, token, transaction));
                Assert.Equal(0L, await ScalarAsync<long>(connection, """
                    SELECT count(*) FROM public."Country"
                    WHERE ("ISO2" IS NOT NULL AND char_length("ISO2") <> 2)
                       OR ("ISO3" IS NOT NULL AND char_length("ISO3") <> 3);
                    """, token, transaction));
                await transaction.CommitAsync(token);
            }
            Assert.Equal(rows, await RowsAsync(connection, after: true, token));
            Assert.Equal(outside, await OutsideAsync(connection, token));
            IsoDefinitionRecorder.Projection(database, "readback", await RowsAsync(connection, true, token), await OutsideAsync(connection, token));
            Assert.Equal(2L, await ScalarAsync<long>(connection, """
                SELECT count(*) FROM pg_attribute WHERE attrelid='public."Country"'::regclass
                AND ((attname='ISO2' AND format_type(atttypid,atttypmod)='character varying(2)')
                  OR (attname='ISO3' AND format_type(atttypid,atttypmod)='character varying(3)'));
                """, token));
        }
    });
    }

    [WindowsLocalRunTheory]
    [InlineData("CREATE INDEX unknown_iso ON public.\"Country\" (\"ISO2\");")]
    [InlineData("CREATE INDEX unknown_expression ON public.\"Country\" (lower(\"ISO2\"::text));")]
    [InlineData("ALTER TABLE public.\"Country\" ADD CONSTRAINT unknown_check CHECK (octet_length(bpcharsend(\"ISO3\")) > 0);")]
    [InlineData("CREATE VIEW public.unknown_view AS SELECT \"ISO2\" FROM public.\"Country\";")]
    [InlineData("ALTER TABLE public.\"Country\" ADD COLUMN unknown_generated text GENERATED ALWAYS AS (\"ISO2\"::text) STORED;")]
    [InlineData("ALTER TABLE public.\"Country\" ALTER COLUMN \"ISO2\" TYPE varchar(2);")]
    public Task Candidate_refuses_dependencies_or_partial_type_state_before_transition(string unexpected)
    {
        return RunOwnedAsync(IsoDefinitionCases.Fault(unexpected, true), unexpected, async (admin, token) =>
    {
        await using var connection = new NpgsqlConnection(admin);
        await connection.OpenAsync(token);
        Assert.Equal("off", await ScalarAsync<string>(connection, "SHOW autovacuum;", token));
        await BootstrapAsync(connection, "negative", token);
        await ExecuteAsync(connection, unexpected, token);
        IsoDefinitionRecorder.Raw("before-rejection", await CaptureDefinitionRawAsync(connection, token));
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(token);
        var rejection = await Assert.ThrowsAsync<PostgresException>(() => CandidateAsync(connection, transaction, token));
        IsoDefinitionRecorder.Rejected("candidate-before-effect", rejection.SqlState);
        await transaction.RollbackAsync(token);
        IsoDefinitionRecorder.Raw("after-rejection", await CaptureDefinitionRawAsync(connection, token));
    });
    }

    private static async Task CreateDatabaseAsync(string admin, string database, CancellationToken token)
    {
        if (database is not ("iso_country_fixture" or "iso_material_fixture")) { throw new InvalidOperationException(); }
        await using var connection = new NpgsqlConnection(admin);
        await connection.OpenAsync(token);
        await ExecuteAsync(connection, "CREATE DATABASE " + database + " TEMPLATE template0 ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C';", token);
    }

    private static async Task BootstrapAsync(NpgsqlConnection connection, string label, CancellationToken token)
    {
        await ExecuteAsync(connection, """
            CREATE COLLATION public.legacy_ci_as (provider=icu,locale='und-u-ks-level2',deterministic=false);
            CREATE TABLE public."Country" (
                "ID" integer GENERATED BY DEFAULT AS IDENTITY,
                "Name" varchar(50) COLLATE public.legacy_ci_as NOT NULL,
                "Continent" varchar(50) COLLATE public.legacy_ci_as,
                "CountryCode" varchar(30) COLLATE public.legacy_ci_as,
                "ISO2" char(2) COLLATE public.legacy_ci_as,
                "ISO3" char(3) COLLATE public.legacy_ci_as,
                "CreatedDate" timestamp DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'),
                "ModifiedDate" timestamp DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'),
                CONSTRAINT "PK_Country" PRIMARY KEY ("ID")
            );
            CREATE TABLE public.retained_other (id integer PRIMARY KEY, note text NOT NULL);
            INSERT INTO public.retained_other VALUES (1,'retained independently');
            SELECT setval('public."Country_ID_seq"',77,false);
            """, token);
        (string? Two, string? Three)[] cases =
        [(null, null), ("", ""), (" ", "  "), ("A", "B"), ("A ", "B  "), ("กข", "ไทย"), ("'\\", "\t'\\"), ("é", "é")];
        foreach (var (two, three) in cases)
        {
            await using var command = new NpgsqlCommand("""
                INSERT INTO public."Country" ("Name","ISO2","ISO3","CreatedDate","ModifiedDate")
                VALUES ($1,$2,$3,timestamp '2000-01-02 03:04:05.123456',NULL);
                """, connection);
            _ = command.Parameters.AddWithValue(label);
            _ = command.Parameters.AddWithValue(NpgsqlTypes.NpgsqlDbType.Text, (object?)two ?? DBNull.Value);
            _ = command.Parameters.AddWithValue(NpgsqlTypes.NpgsqlDbType.Text, (object?)three ?? DBNull.Value);
            _ = await command.ExecuteNonQueryAsync(token);
        }
    }

    private static Task CandidateAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, CancellationToken token)
    {
        return ExecuteAsync(connection, """
            SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='20s';
            LOCK TABLE public."Country" IN ACCESS EXCLUSIVE MODE;
            DO $guard$
            BEGIN
              IF (SELECT count(*) FROM pg_attribute WHERE attrelid='public."Country"'::regclass
                  AND ((attname='ISO2' AND format_type(atttypid,atttypmod)='character(2)')
                    OR (attname='ISO3' AND format_type(atttypid,atttypmod)='character(3)'))
                  AND NOT attnotnull AND attgenerated='' AND attidentity=''
                  AND attcollation='public.legacy_ci_as'::regcollation) <> 2
                 OR EXISTS (SELECT 1 FROM pg_depend d JOIN pg_attribute a
                      ON a.attrelid=d.refobjid AND a.attnum=d.refobjsubid
                      WHERE d.refclassid='pg_class'::regclass AND d.refobjid='public."Country"'::regclass
                      AND a.attname IN ('ISO2','ISO3'))
              THEN RAISE EXCEPTION 'Unreviewed ISO preimage or dependency'; END IF;
            END $guard$;
            ALTER TABLE public."Country" ALTER COLUMN "ISO2" TYPE varchar(2) COLLATE public.legacy_ci_as
                USING rpad("ISO2"::text,2,' ');
            ALTER TABLE public."Country" ALTER COLUMN "ISO3" TYPE varchar(3) COLLATE public.legacy_ci_as
                USING rpad("ISO3"::text,3,' ');
            """, token, transaction);
    }

    private static Task<string> RowsAsync(NpgsqlConnection connection, bool after, CancellationToken token, NpgsqlTransaction? transaction = null)
    {
        string two = after ? "convert_to(\"ISO2\",'UTF8')" : "bpcharsend(\"ISO2\")";
        string three = after ? "convert_to(\"ISO3\",'UTF8')" : "bpcharsend(\"ISO3\")";
        return ScalarAsync<string>(connection, "SELECT encode(sha256(convert_to(jsonb_agg(jsonb_build_array(\"ID\",encode(" +
            two + ",'hex'),encode(" + three + ",'hex'),\"ISO2\" IS NULL,\"ISO3\" IS NULL) ORDER BY \"ID\")::text,'UTF8')),'hex') FROM public.\"Country\";", token, transaction);
    }

    // Type rewrites may change heap/index relfilenodes. This component proof compares stable catalog definitions,
    // object OIDs, all non-operand attributes, dependencies, outside rows and complete sequence state.
    // It does not certify a production-wide raw catalog transition whitelist.
    private static Task<string> OutsideAsync(NpgsqlConnection connection, CancellationToken token, NpgsqlTransaction? transaction = null)
    {
        return ScalarAsync<string>(connection, """
            SELECT encode(sha256(convert_to(jsonb_build_object(
              'rows',(SELECT jsonb_agg(to_jsonb(c)-'ISO2'-'ISO3' ORDER BY "ID") FROM public."Country" c),
              'other',(SELECT jsonb_agg(to_jsonb(c) ORDER BY id) FROM public.retained_other c),
              'attributes',(SELECT jsonb_agg(to_jsonb(a) ORDER BY a.attnum) FROM pg_attribute a
                  WHERE a.attrelid='public."Country"'::regclass AND a.attnum>0 AND a.attname NOT IN ('ISO2','ISO3')),
              'constraints',(SELECT jsonb_agg(to_jsonb(c) ORDER BY c.oid) FROM pg_constraint c WHERE c.conrelid='public."Country"'::regclass),
              'indexes',(SELECT jsonb_agg(to_jsonb(i) ORDER BY i.indexrelid) FROM pg_index i WHERE i.indrelid='public."Country"'::regclass),
              'defaults',(SELECT jsonb_agg(to_jsonb(d) ORDER BY d.adnum) FROM pg_attrdef d WHERE d.adrelid='public."Country"'::regclass),
              'sequenceDefinition',(SELECT to_jsonb(s) FROM pg_sequence s WHERE s.seqrelid='public."Country_ID_seq"'::regclass),
              'sequenceState',(SELECT jsonb_build_object('last_value',s.last_value,'log_cnt',s.log_cnt,'is_called',s.is_called)
                  FROM public."Country_ID_seq" s),
              'dependencies',(SELECT jsonb_agg(to_jsonb(d) ORDER BY d.classid,d.objid,d.objsubid,d.refclassid,d.refobjid,d.refobjsubid,d.deptype)
                  FROM pg_depend d WHERE (d.objid IN ('public."Country"'::regclass,'public."Country_ID_seq"'::regclass)
                    OR d.refobjid IN ('public."Country"'::regclass,'public."Country_ID_seq"'::regclass))
                    AND NOT (d.classid='pg_class'::regclass AND d.objid='public."Country"'::regclass AND d.objsubid IN (5,6)))
            )::text,'UTF8')),'hex');
            """, token, transaction);
    }

    private static async Task<T> ScalarAsync<T>(NpgsqlConnection connection, string sql, CancellationToken token, NpgsqlTransaction? transaction = null)
    {
        await using var command = new NpgsqlCommand(sql, connection, transaction) { CommandTimeout = 30 };
        return (T)(await command.ExecuteScalarAsync(token) ?? throw new InvalidOperationException("Missing proof evidence"));
    }
}

using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

/// <summary>Run-owned PostgreSQL probes; no production authorization or migrated-source receipt.</summary>
[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class CurrentConsumerSchemaV2NativeTests(PostgreSqlAdapterFixture fixture)
{
    [Fact]
    public async Task CurrentUploadPhysicalContractRejectsColumnDefaultForeignKeyAndUniqueIndexDrift()
    {
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        ShadowDatabase shadow = await target.CreateUniqueEmptyShadowAsync("Upload", $"legacy_shadow_current_upload_{Guid.NewGuid():N}",
            Guid.NewGuid().ToString("D"), default);
        DatabaseSchemaPlan source = CurrentConsumerSchemaV2Tests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV2)
            .Databases.Single(database => database.Database == "Upload");
        string connectionString = new NpgsqlConnectionStringBuilder(fixture.ShadowAdminConnectionString) { Database = shadow.Name }.ConnectionString;
        try
        {
            await using (var bootstrapConnection = new NpgsqlConnection(connectionString))
            {
                await bootstrapConnection.OpenAsync();
                await using var bootstrapTransaction = await bootstrapConnection.BeginTransactionAsync();
                await using var bootstrap = new PostgreSqlWholeDatabaseTransaction(bootstrapConnection, bootstrapTransaction, ownsResources: false);
                await bootstrap.ApplySchemaAsync(source, default);
                await bootstrap.FinalizeSchemaAsync(source, default);
                var (SchemaSha256, Components, Columns) = await bootstrap.InspectSchemaWithComponentsAsync(source, default);
                foreach (TableCopyPlan table in ApprovedConsumerColumnOverlayManifest.ComposePhysical(source))
                {
                    var expected = PostgreSqlSchemaFingerprint.ComputeExpectedComponents(table);
                    var observed = Components.Single(component => component.Schema == table.TargetSchema && component.Table == table.TargetTable);
                    await using var checks = new NpgsqlCommand("SELECT conname || ': ' || pg_get_expr(conbin,conrelid) FROM pg_constraint WHERE contype='c' AND connamespace='public'::regnamespace ORDER BY conname", bootstrapConnection, bootstrapTransaction);
                    var expressions = new List<string>();
                    await using (var reader = await checks.ExecuteReaderAsync())
                    { while (await reader.ReadAsync()) { expressions.Add(reader.GetString(0)); } }
                    Assert.True(expected == observed, $"{table.TargetTable}: {string.Join(';', expressions)}");
                }
                Assert.Equal(source.TargetSchemaSha256, await bootstrap.InspectSchemaAsync(source, default));
                // Commit only this empty, run-owned schema fixture; this is not shadow-copy admission.
                await bootstrapTransaction.CommitAsync();
            }
            await using var connection = new NpgsqlConnection(connectionString);
            await connection.OpenAsync();
            foreach (string mutation in Mutations)
            {
                await using var transaction = await connection.BeginTransactionAsync();
                await using (var command = new NpgsqlCommand(mutation, connection, transaction))
                { _ = await command.ExecuteNonQueryAsync(); }
                await using var inspection = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
                Assert.NotEqual(source.TargetSchemaSha256, await inspection.InspectSchemaAsync(source, default));
                await transaction.RollbackAsync();
            }
            await using (var transaction = await connection.BeginTransactionAsync())
            {
                await using var inspection = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
                Assert.Equal(source.TargetSchemaSha256, await inspection.InspectSchemaAsync(source, default));
                ApprovedTargetExtensionState state = await ApprovedTargetExtensionStateInspector.InspectAsync(connection, transaction, source, default);
                Assert.Equal(5, state.Tables.Count);
                Assert.All(state.Tables, table => Assert.Equal(0, table.RowCount));
                Assert.Equal(64, ApprovedTargetExtensionStateInspector.ComputeSha256(source, state).Length);
                await transaction.RollbackAsync();
            }
            await RequireConstraintsAsync(connection);
            await RequireArrayShapeAsync(connection, source);
        }
        finally { await target.DeleteRunOwnedShadowAsync(shadow, default); }
    }

    private static async Task RequireArrayShapeAsync(NpgsqlConnection connection, DatabaseSchemaPlan schema)
    {
        const string session = "11111111-1111-1111-1111-111111111111";
        TableCopyPlan table = ApprovedTargetExtensionManifest.TablesFor(schema)
            .Single(table => table.TargetTable == "InstantQuoteFinalization");
        foreach (string shape in new[] { "empty", "lower-bound", "multidimensional", "null-element" })
        {
            await using var transaction = await connection.BeginTransactionAsync();
            await ExecuteAsync(connection, transaction, $"""
                INSERT INTO public."InstantQuoteUploadSession" ("Id","OwnerSubject","IsAuthenticated","TokenHash","ExpiresAt","CreatedAt")
                VALUES ('{session}',NULL,false,decode(repeat('ab',32),'hex'),'2031-01-02Z','2031-01-01Z');
                """);
            await ExecuteAsync(connection, transaction, Finalization(session, "22222222-2222-2222-2222-222222222222", 1));
            string? expression = shape switch
            {
                "lower-bound" => "'[2:2]={33333333-3333-3333-3333-333333333333}'::uuid[]",
                "multidimensional" => "ARRAY[['33333333-3333-3333-3333-333333333333'::uuid]]",
                "null-element" => "ARRAY[NULL::uuid]",
                _ => null,
            };
            if (expression is not null)
            {
                await ExecuteAsync(connection, transaction,
                    $"UPDATE public.\"InstantQuoteFinalization\" SET \"SelectedFileIds\" = {expression};");
            }
            await using var inspection = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
            if (shape == "empty")
            {
                TableReconciliationEvidence evidence = await inspection.InspectTableAsync(table, default);
                Assert.Equal(1, evidence.RowCount);
                Assert.Equal(0, evidence.NullCounts["SelectedFileIds"]);
            }
            else
            {
                MigrationExecutionException failure = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
                    inspection.InspectTableAsync(table, default));
                Assert.Equal("target_uuid_array_shape_invalid", failure.Code);
            }
            await transaction.RollbackAsync();
        }
    }
    private static async Task RequireConstraintsAsync(NpgsqlConnection connection)
    {
        const string session = "11111111-1111-1111-1111-111111111111";
        foreach (string fault in new[] { "foreign-key", "unique-key", "check" })
        {
            await using var transaction = await connection.BeginTransactionAsync();
            await ExecuteAsync(connection, transaction, $"""
                INSERT INTO public."InstantQuoteUploadSession" ("Id","OwnerSubject","IsAuthenticated","TokenHash","ExpiresAt","CreatedAt")
                VALUES ('{session}',NULL,false,decode(repeat('ab',32),'hex'),'2031-01-02Z','2031-01-01Z');
                """);
            if (fault == "unique-key")
            {
                await ExecuteAsync(connection, transaction, Finalization(session, "22222222-2222-2222-2222-222222222222", 1));
            }
            string insert = Finalization(fault == "foreign-key" ? "33333333-3333-3333-3333-333333333333" : session,
                "44444444-4444-4444-4444-444444444444", fault == "check" ? 0 : 1);
            PostgresException failure = await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(connection, transaction, insert));
            Assert.Equal(fault switch { "foreign-key" => "23503", "unique-key" => "23505", _ => "23514" }, failure.SqlState);
            await transaction.RollbackAsync();
        }
    }

    private static string Finalization(string session, string identity, int request)
    {
        return $"""
        INSERT INTO public."InstantQuoteFinalization" ("Id","SessionId","IdempotencyKeyHash","RequestFingerprint","QuotationRequestId","SelectedFileIds","State","CreatedAt","ModifiedAt")
        VALUES ('{identity}','{session}',decode(repeat('ab',32),'hex'),repeat('a',64),{request},ARRAY[]::uuid[],'Prepared','2031-01-01Z','2031-01-01Z');
        """;
    }

    private static async Task ExecuteAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, string sql)
    {
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        _ = await command.ExecuteNonQueryAsync();
    }

    private static readonly string[] Mutations =
    [
        "ALTER TABLE public.\"InstantQuoteUploadFile\" ADD COLUMN \"Unreviewed\" integer;",
        "ALTER TABLE public.\"InstantQuoteUploadFile\" ALTER COLUMN \"TemporaryCleanupCompleted\" SET DEFAULT true;",
        "ALTER TABLE public.\"InstantQuoteUploadFile\" DROP CONSTRAINT \"FK_InstantQuoteUploadFile_InstantQuoteUploadSession_SessionId\";",
        "ALTER TABLE public.\"InstantQuoteUploadFile\" ALTER COLUMN \"OriginalFileName\" DROP NOT NULL;",
        "DROP INDEX public.\"IX_InstantQuoteUploadFile_SessionId_IdempotencyKeyHash\";",
        "ALTER TABLE public.\"InstantQuoteUploadFile\" ALTER COLUMN \"OriginalFileName\" TYPE character varying(1024) COLLATE \"POSIX\";",
        "CREATE TABLE public.\"UnreviewedOwnedState\" (\"ID\" integer NOT NULL);",
        "ALTER TABLE public.\"StorageMoveJournal\" DROP CONSTRAINT \"CK_StorageMoveJournal_DestinationGeneration\"; ALTER TABLE public.\"StorageMoveJournal\" ADD CONSTRAINT \"CK_StorageMoveJournal_DestinationGeneration\" CHECK (\"DestinationGeneration\" IS NULL OR \"DestinationGeneration\" >= 0);",
        "ALTER TABLE public.\"InstantQuoteUploadFile\" DROP CONSTRAINT \"CK_InstantQuoteUploadFile_Fingerprint\"; ALTER TABLE public.\"InstantQuoteUploadFile\" ADD CONSTRAINT \"CK_InstantQuoteUploadFile_Fingerprint\" CHECK (\"RequestFingerprint\" ~ '^[0-9a-f]{63}$');",
    ];
}

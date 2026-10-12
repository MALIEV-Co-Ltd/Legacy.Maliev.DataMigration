using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentConsumerSchemaV2Tests
{
    private static readonly string[] NewlyOwnedDatabases = ["Customer", "Order", "Upload"];

    [Theory]
    [InlineData("uuid[][]")]
    [InlineData("text[]")]
    [InlineData("uuid[]; DROP TABLE app")]
    public void ArrayTypePolicyAcceptsOnlyReviewedUuidArray(string unreviewed)
    {
        Assert.Equal("uuid[]", PostgreSqlTypePolicy.Validate("uuid[]"));
        Assert.Equal("target_type_forbidden", Assert.Throws<MigrationExecutionException>(() => PostgreSqlTypePolicy.Validate(unreviewed)).Code);
    }
    [Fact]
    public void ClosedSelectionAddsEightOwnedTablesWithoutChangingOneHundredSourceProjections()
    {
        FreshSchemaPlan old = Schema(ConsumerOverlaySelection.CurrentConsumerColumnsV1);
        FreshSchemaPlan current = Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV2);
        Assert.Equal(23, current.Databases.Count);
        Assert.Equal(100, current.Databases.Sum(database => database.Tables.Count));
        Assert.Equal(JsonSerializer.Serialize(old.Databases.Select(database => database.Tables)),
            JsonSerializer.Serialize(current.Databases.Select(database => database.Tables)));
        Assert.True(ApprovedConsumerOverlaySelection.IsApproved(old));
        Assert.True(ApprovedConsumerOverlaySelection.IsApproved(current));
        Assert.True(ApprovedConsumerOverlaySelection.IsCurrent(current));
        string[] changedDatabases = ["Customer", "CustomerIdentity", "EmployeeIdentity", "Invoice", "Order", "Quotation", "QuotationRequest", "Upload"];
        Assert.Equal(changedDatabases, current.Databases.Where(database => database.TargetExtensionProfile !=
            old.Databases.Single(prior => prior.Database == database.Database).TargetExtensionProfile).Select(database => database.Database));
        foreach (DatabaseSchemaPlan database in current.Databases.Where(database => !changedDatabases.Contains(database.Database, StringComparer.Ordinal)))
        {
            Assert.Equal(JsonSerializer.Serialize(old.Databases.Single(prior => prior.Database == database.Database)), JsonSerializer.Serialize(database));
        }
        Assert.Equal(8, NewlyOwnedDatabases.Sum(database =>
            ApprovedTargetExtensionManifest.TablesFor(current.Databases.Single(item => item.Database == database)).Count));
    }

    [Theory]
    [InlineData("Customer")]
    [InlineData("CustomerIdentity")]
    [InlineData("EmployeeIdentity")]
    [InlineData("Invoice")]
    [InlineData("Order")]
    [InlineData("Quotation")]
    [InlineData("QuotationRequest")]
    [InlineData("Upload")]
    public void PartialActivationAndCrossDatabaseProfilesCannotBecomeApproved(string database)
    {
        FreshSchemaPlan current = Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV2);
        FreshSchemaPlan partial = current with
        {
            Databases = [.. current.Databases.Select(item => item.Database == database
                ? item with { TargetExtensionProfile = ApprovedConsumerOverlaySelection.ProfileForDatabase(database, ConsumerOverlaySelection.CurrentConsumerColumnsV1) }
                : item)],
        };
        Assert.False(ApprovedConsumerOverlaySelection.IsApproved(partial));
        DatabaseSchemaPlan wrong = current.Databases.Single(item => item.Database == database) with
        { TargetExtensionProfile = ApprovedConsumerOverlaySelection.ProfileForDatabase(database == "Upload" ? "Order" : "Upload", ConsumerOverlaySelection.CurrentConsumerSchemaV2) };
        _ = Assert.Throws<MigrationExecutionException>(() => PostgreSqlSchemaFingerprint.ComputeExpected(wrong));
    }

    [Fact]
    public void EightCurrentShapesMatchCommittedMigrationColumnsAndKeysWithExplicitStringCollations()
    {
        Dictionary<string, string> columnContracts = new(StringComparer.Ordinal)
        {
            ["CustomerCreateOperation"] = "Key:uuid|ActorHash:character varying(64)|RequestHash:character varying(64)|CustomerId:integer|ResponseJson:jsonb|CreatedAt:timestamp with time zone",
            ["QuotationProfileCompletionOperation"] = "CustomerId:integer|Key:uuid|ActorHash:character varying(64)|RequestHash:character varying(64)|CompletionId:uuid|Changed:boolean|CreatedAt:timestamp with time zone",
            ["StorageMoveJournal"] = "OperationId:uuid|ScanClean:boolean|SourceBucket:character varying(255)|SourceObjectName:character varying(1024)|SourceGeneration:bigint|DestinationBucket:character varying(255)|DestinationObjectName:character varying(1024)|DestinationGeneration:bigint|State:character varying(32)|CreatedAt:timestamp with time zone|ModifiedAt:timestamp with time zone",
            ["QuarantineUploadIntent"] = "OperationId:uuid|ParentOperationId:uuid|Bucket:character varying(255)|ObjectName:character varying(1024)|ContentType:character varying(255)|DeclaredSize:bigint|AcknowledgedGeneration:bigint|State:character varying(32)|CreatedAt:timestamp with time zone|ModifiedAt:timestamp with time zone",
            ["InstantQuoteUploadSession"] = "Id:uuid|OwnerSubject:character varying(512)|IsAuthenticated:boolean|TokenHash:bytea|ExpiresAt:timestamp with time zone|CreatedAt:timestamp with time zone",
            ["InstantQuoteFinalization"] = "Id:uuid|SessionId:uuid|IdempotencyKeyHash:bytea|RequestFingerprint:character(64)|QuotationRequestId:integer|SelectedFileIds:uuid[]|State:character varying(16)|CreatedAt:timestamp with time zone|ModifiedAt:timestamp with time zone",
            ["InstantQuoteUploadFile"] = "Id:uuid|SessionId:uuid|IdempotencyKeyHash:bytea|RequestFingerprint:character(64)|OriginalFileName:character varying(1024)|ValidatedExtension:character varying(16)|ValidatedContentType:character varying(255)|ExpectedSha256:character(64)|ActualSha256:character(64)|ActualSizeBytes:bigint|GcsGeneration:bigint|TemporaryCleanupCompleted:boolean|TemporaryBucket:character varying(255)|TemporaryObjectName:character varying(1024)|FinalBucket:character varying(255)|FinalObjectName:character varying(1024)|FinalizedQuotationRequestId:integer|State:character varying(16)|CreatedAt:timestamp with time zone|ModifiedAt:timestamp with time zone",
            ["OrderDeletionIntent"] = "OrderId:integer|DeletionId:uuid|RequestedAtUtc:timestamp with time zone|StatusCleanupCompletedAtUtc:timestamp with time zone|CompletedAtUtc:timestamp with time zone|AttemptCount:integer|NextAttemptAtUtc:timestamp with time zone",
        };
        Dictionary<string, string[]> nullableContracts = new(StringComparer.Ordinal)
        {
            ["CustomerCreateOperation"] = [],
            ["QuotationProfileCompletionOperation"] = [],
            ["StorageMoveJournal"] = ["DestinationGeneration"],
            ["QuarantineUploadIntent"] = ["AcknowledgedGeneration"],
            ["InstantQuoteUploadSession"] = ["OwnerSubject"],
            ["InstantQuoteFinalization"] = [],
            ["InstantQuoteUploadFile"] = ["ActualSha256", "ActualSizeBytes", "GcsGeneration", "FinalBucket", "FinalObjectName", "FinalizedQuotationRequestId"],
            ["OrderDeletionIntent"] = ["StatusCleanupCompletedAtUtc", "CompletedAtUtc"],
        };
        TableCopyPlan[] tables = [.. Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV2).Databases
            .Where(database => database.Database is "Customer" or "Upload" or "Order").SelectMany(ApprovedTargetExtensionManifest.TablesFor)];
        Assert.Equal(columnContracts.Keys.Order(StringComparer.Ordinal), tables.Select(table => table.TargetTable).Order(StringComparer.Ordinal));
        foreach (TableCopyPlan table in tables)
        {
            Assert.Equal("target-only", table.SourceSchema);
            Assert.Equal("public", table.TargetSchema);
            Assert.Equal(columnContracts[table.TargetTable], string.Join('|', table.OrderedColumns.Select(column => $"{column}:{table.ColumnTypes[column]}")));
            Assert.Equal("PK_" + table.TargetTable, table.PrimaryKey!.Name);
            Assert.Equal(table.PrimaryKey.Columns, table.OrderByColumns);
            Assert.Empty(table.Identities);
            Assert.Empty(table.GeneratedColumns);
            Assert.Equal(nullableContracts[table.TargetTable], table.NullableColumns);
            string[] strings = [.. table.OrderedColumns.Where(column => IsString(table.ColumnTypes[column]))];
            Assert.Equal(strings.Order(StringComparer.Ordinal), table.Collations.Keys.Order(StringComparer.Ordinal));
            Assert.All(table.Collations.Values, collation => Assert.Equal("C", collation));
        }
        Assert.Equal<string>(["CustomerId", "Key"], tables.Single(table => table.TargetTable == "QuotationProfileCompletionOperation").PrimaryKey!.Columns);
        Assert.Equal("false", tables.Single(table => table.TargetTable == "InstantQuoteUploadFile").DefaultExpressions["TemporaryCleanupCompleted"]);
        Assert.All(tables.Where(table => table.TargetTable != "InstantQuoteUploadFile"), table => Assert.Empty(table.DefaultExpressions));
        foreach (TableCopyPlan table in tables.Where(table => table.TargetTable is "InstantQuoteUploadFile" or "InstantQuoteFinalization"))
        {
            ForeignKeyCopyPlan foreignKey = Assert.Single(table.ForeignKeys);
            Assert.Equal<string>(["SessionId"], foreignKey.Columns);
            Assert.Equal("InstantQuoteUploadSession", foreignKey.ReferencedTable);
            Assert.Equal<string>(["Id"], foreignKey.ReferencedColumns);
            Assert.Equal(ReferentialAction.Cascade, foreignKey.OnDelete);
            Assert.True(Assert.Single(table.Indexes).Unique);
            Assert.Equal<string>(["SessionId", "IdempotencyKeyHash"], Assert.Single(table.Indexes).Columns);
        }
        Assert.Equal("\"CompletedAtUtc\" IS NULL", tables.Single(table => table.TargetTable == "OrderDeletionIntent").Indexes.Single(index => !index.Unique).FilterPredicate);
    }

    [Theory]
    [InlineData("Customer")]
    [InlineData("Upload")]
    [InlineData("Order")]
    public void OwnedTableCannotBePromotedIntoTheSignedSourceInventory(string database)
    {
        DatabaseSchemaPlan schema = Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV2).Databases.Single(item => item.Database == database);
        TableCopyPlan owned = ApprovedTargetExtensionManifest.TablesFor(schema)[0];
        _ = Assert.Throws<MigrationExecutionException>(() => PostgreSqlSchemaFingerprint.ComputeExpected(schema with
        { Tables = [.. schema.Tables, owned with { SourceSchema = "dbo" }] }));
    }

    [Fact]
    public void VersionTwoMakesExistingThirtyOneOwnedTextColumnsExplicitCWithoutChangingPriorProfiles()
    {
        FreshSchemaPlan prior = Schema(ConsumerOverlaySelection.CurrentConsumerColumnsV1);
        FreshSchemaPlan current = Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV2);
        int existingTextColumns = 0;
        foreach (string database in new[] { "Invoice", "CustomerIdentity", "EmployeeIdentity", "QuotationRequest" })
        {
            DatabaseSchemaPlan oldDatabase = prior.Databases.Single(item => item.Database == database);
            DatabaseSchemaPlan newDatabase = current.Databases.Single(item => item.Database == database);
            foreach (TableCopyPlan oldTable in ApprovedTargetExtensionManifest.TablesFor(oldDatabase))
            {
                TableCopyPlan selected = ApprovedTargetExtensionManifest.TablesFor(newDatabase).Single(table => table.TargetTable == oldTable.TargetTable);
                string[] strings = [.. oldTable.OrderedColumns.Where(column => IsString(oldTable.ColumnTypes[column]))];
                existingTextColumns += strings.Length;
                Assert.All(strings, column => Assert.Equal("C", selected.Collations[column]));
                Assert.Equal(JsonSerializer.Serialize(oldTable), JsonSerializer.Serialize(selected with { Collations = oldTable.Collations }));
            }
        }
        // The sixth shared table is produced by the reviewed outbox disposition, not the extension inventory.
        DatabaseSchemaPlan quotation = current.Databases.Single(item => item.Database == "Quotation");
        TableCopyPlan[] sourceTables =
        [
            quotation.Tables[0],
            ApprovedSourceDispositionManifestTests.Outbox(CurrentQuotationSourceContract.GoogleAnalyticsOutbox,
                "PK_GoogleAnalyticsOutbox", "UX_GoogleAnalyticsOutbox_EventKey", uniqueIndex: true),
            ApprovedSourceDispositionManifestTests.Outbox(CurrentQuotationSourceContract.QuotationOutcomeOutbox,
                "PK_QuotationOutcomeOutbox", "UQ_QuotationOutcomeOutbox_EventKey", uniqueIndex: false),
        ];
        quotation = quotation with
        {
            Tables = sourceTables,
            SourceDispositionProfile = ApprovedSourceDispositionManifest.QuotationOutboxesV1,
            SourceTableDispositions = ApprovedSourceDispositionManifest.DispositionsForDatabase("Quotation", sourceTables),
        };
        DatabaseSchemaPlan oldQuotation = quotation with { TargetExtensionProfile = ApprovedConsumerColumnOverlayManifest.QuotationV1 };
        TableCopyPlan oldOutcome = ApprovedSourceDispositionManifest.TargetTablesFor(oldQuotation).Single(table => table.TargetTable == "QuotationAcceptedOutcome");
        TableCopyPlan newOutcome = ApprovedSourceDispositionManifest.TargetTablesFor(quotation).Single(table => table.TargetTable == "QuotationAcceptedOutcome");
        string[] outcomeStrings = [.. oldOutcome.OrderedColumns.Where(column => IsString(oldOutcome.ColumnTypes[column]))];
        Assert.Equal(2, outcomeStrings.Length);
        Assert.Equal(31, existingTextColumns + outcomeStrings.Length);
        Assert.Empty(oldOutcome.Collations);
        Assert.All(outcomeStrings, column => Assert.Equal("C", newOutcome.Collations[column]));
        Assert.Equal(JsonSerializer.Serialize(oldOutcome), JsonSerializer.Serialize(newOutcome with { Collations = oldOutcome.Collations }));
        Assert.Equal(JsonSerializer.Serialize(ApprovedSourceDispositionManifest.TargetTablesFor(oldQuotation).Single(table => table.TargetSchema == "legacy_compatibility")),
            JsonSerializer.Serialize(ApprovedSourceDispositionManifest.TargetTablesFor(quotation).Single(table => table.TargetSchema == "legacy_compatibility")));
        Assert.NotNull(ApprovedConsumerColumnOverlayManifest.For(quotation));
    }

    [Theory]
    [InlineData("Customer")]
    [InlineData("Order")]
    [InlineData("Upload")]
    public void StateRequiresCompleteTableColumnRelationshipAndSequenceEvidence(string database)
    {
        DatabaseSchemaPlan schema = Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV2).Databases.Single(item => item.Database == database);
        ApprovedTargetExtensionState original = State(schema);
        string digest = ApprovedTargetExtensionStateInspector.ComputeSha256(schema, original);
        Assert.Equal(64, digest.Length);
        TableReconciliationEvidence first = original.Tables[0];
        foreach (string fault in new[] { "missing-table", "extra-table", "null-field", "extra-field", "negative-null", "content", "sequence" })
        {
            var nulls = first.NullCounts.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
            if (fault == "null-field") { _ = nulls.Remove(nulls.Keys.First()); }
            if (fault == "extra-field") { nulls.Add("Unreviewed", 0); }
            if (fault == "negative-null") { nulls[nulls.Keys.First()] = -1; }
            ApprovedTargetExtensionState changed = original with
            {
                Tables = fault switch
                {
                    "missing-table" => [.. original.Tables.Skip(1)],
                    "extra-table" => [.. original.Tables, first with { Table = "public.Unreviewed" }],
                    "content" => [first with { ContentSha256 = new string('9', 64) }, .. original.Tables.Skip(1)],
                    _ => [first with { NullCounts = nulls }, .. original.Tables.Skip(1)],
                },
                SequenceNextValues = fault == "sequence" ? new Dictionary<string, long> { ["public.Unreviewed.ID"] = 1 } : original.SequenceNextValues,
            };
            if (fault == "content")
            {
                Assert.NotEqual(digest, ApprovedTargetExtensionStateInspector.ComputeSha256(schema, changed));
                _ = Assert.Throws<MigrationExecutionException>(() => ApprovedTargetExtensionStateInspector.Compare(schema, original, changed));
            }
            else { _ = Assert.Throws<MigrationExecutionException>(() => ApprovedTargetExtensionStateInspector.ComputeSha256(schema, changed)); }
        }
        foreach (TableReconciliationEvidence evidence in original.Tables.Where(table => table.ForeignKeyOrphanCounts.Count != 0))
        {
            foreach (string fault in new[] { "orphan", "missing-orphan", "missing-relationship", "extra-relationship" })
            {
                var orphans = evidence.ForeignKeyOrphanCounts.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
                var relationships = evidence.ForeignKeyRelationshipCounts.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
                if (fault == "orphan") { orphans[orphans.Keys.First()] = 1; }
                if (fault == "missing-orphan") { orphans.Clear(); }
                if (fault == "missing-relationship") { relationships.Clear(); }
                if (fault == "extra-relationship") { relationships.Add("Unreviewed", 1); }
                ApprovedTargetExtensionState changed = original with
                { Tables = [.. original.Tables.Select(table => table.Table == evidence.Table ? table with { ForeignKeyOrphanCounts = orphans, ForeignKeyRelationshipCounts = relationships } : table)] };
                _ = Assert.Throws<MigrationExecutionException>(() => ApprovedTargetExtensionStateInspector.ComputeSha256(schema, changed));
            }
        }
    }

    internal static FreshSchemaPlan Schema(ConsumerOverlaySelection selection)
    {
        int[] counts = [2, 2, 2, 6, 9, 3, 2, 7, 9, 4, 3, 1, 8, 2, 6, 4, 7, 5, 7, 3, 4, 3, 1];
        return new("2.0", new DateTimeOffset(2031, 1, 1, 0, 0, 0, TimeSpan.Zero), new string('a', 40),
            [.. DatabaseInventory.ActiveDatabases.Select((database, index) => Database(database, counts[index], selection))]);
    }

    private static DatabaseSchemaPlan Database(string database, int count, ConsumerOverlaySelection selection)
    {
        string name = database == "CustomerIdentity" ? "AspNetUsers" : database == "Quotation" ? "Quotation" : "Probe";
        string key = database == "CustomerIdentity" ? "Id" : "ID";
        TableCopyPlan root = new("dbo", name, "public", name, [key, "Value"], [key])
        {
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal) { [key] = database == "CustomerIdentity" ? "character varying(450)" : "integer", ["Value"] = "text" },
            PrimaryKey = new("PK_" + name, [key]),
        };
        DatabaseSchemaPlan schema = new(database, "1.0", new string('b', 64), new string('c', 64),
            [root, .. Enumerable.Range(1, count - 1).Select(index => root with { SourceTable = $"Probe{index}", TargetTable = $"Probe{index}", PrimaryKey = new($"PK_Probe{index}", [key]) })])
        { TargetExtensionProfile = ApprovedConsumerOverlaySelection.ProfileForDatabase(database, selection) };
        return schema with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(schema) };
    }

    private static ApprovedTargetExtensionState State(DatabaseSchemaPlan schema)
    {
        return new(
        [.. ApprovedTargetExtensionManifest.TablesFor(schema).Select(table => new TableReconciliationEvidence(
            $"{table.TargetSchema}.{table.TargetTable}", 1, new string('d', 64), new string('e', 64),
            table.OrderedColumns.ToDictionary(column => column, _ => 0L, StringComparer.Ordinal),
            table.ForeignKeys.ToDictionary(key => key.Name, _ => 0L, StringComparer.Ordinal))
        { ForeignKeyRelationshipCounts = table.ForeignKeys.ToDictionary(key => key.Name, _ => 1L, StringComparer.Ordinal) })],
        new Dictionary<string, long>(StringComparer.Ordinal));
    }

    private static bool IsString(string type)
    {
        return type == "text" || type.StartsWith("character", StringComparison.Ordinal);
    }
}

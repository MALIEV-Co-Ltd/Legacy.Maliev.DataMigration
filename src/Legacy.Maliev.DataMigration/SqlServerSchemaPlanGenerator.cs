using System.Globalization;
using System.Text.RegularExpressions;
using Microsoft.Data.SqlClient;

namespace Legacy.Maliev.DataMigration;

public sealed partial class SqlServerMigrationSource
{
    public async Task<DatabaseSchemaPlan> GenerateDatabasePlanAsync(string database, CancellationToken cancellationToken)
    {
        SnapshotLease lease = GetSnapshot(database);
        SourceSchemaEvidence schema = await InspectSchemaAsync(database, cancellationToken).ConfigureAwait(false);
        IReadOnlyDictionary<(string Schema, string Table), ColumnDetails[]> columns =
            await ReadColumnDetailsAsync(lease, cancellationToken).ConfigureAwait(false);
        IReadOnlyDictionary<(string Schema, string Table), IndexDetails[]> indexes =
            await ReadIndexDetailsAsync(lease, cancellationToken).ConfigureAwait(false);
        IReadOnlyDictionary<(string Schema, string Table), ForeignKeyDetails[]> foreignKeys =
            await ReadForeignKeyDetailsAsync(lease, cancellationToken).ConfigureAwait(false);
        IReadOnlyDictionary<(string Schema, string Table), CheckDetails[]> checks =
            await ReadCheckDetailsAsync(lease, cancellationToken).ConfigureAwait(false);

        var tables = new List<TableCopyPlan>(schema.Tables.Count);
        foreach (SourceTableInventory inventory in schema.Tables)
        {
            var key = (inventory.SourceSchema, inventory.SourceTable);
            ColumnDetails[] tableColumns = columns.GetValueOrDefault(key) ??
                throw new MigrationExecutionException("source_schema_plan_drift", "Column metadata disappeared during schema-plan generation.");
            IndexDetails[] tableIndexes = indexes.GetValueOrDefault(key) ?? [];
            ForeignKeyDetails[] tableForeignKeys = foreignKeys.GetValueOrDefault(key) ?? [];
            CheckDetails[] tableChecks = checks.GetValueOrDefault(key) ?? [];
            PrimaryKeyCopyPlan? primaryKey = CreatePrimaryKey(tableIndexes);
            UniqueConstraintCopyPlan[] uniqueConstraints = CreateUniqueConstraints(tableIndexes);
            string[] nullable = [.. tableColumns.Where(column => column.Nullable).Select(column => column.Column)];
            IReadOnlyList<string> ordering = primaryKey?.Columns ?? uniqueConstraints
                .FirstOrDefault(unique => !unique.Columns.Intersect(nullable, StringComparer.Ordinal).Any())?.Columns ??
                throw new MigrationExecutionException("source_table_total_order_missing", "Every source table requires a non-null unique ordering key.");
            string targetSchema = TargetSchema(inventory.SourceSchema);
            var table = new TableCopyPlan(
                inventory.SourceSchema,
                inventory.SourceTable,
                targetSchema,
                inventory.SourceTable,
                inventory.OrderedColumns,
                ordering)
            {
                SourceColumnTypes = inventory.Columns.ToDictionary(column => column.Column, column => column.DeclaredType, StringComparer.Ordinal),
                SourceColumns = inventory.Columns,
                ColumnTypes = inventory.Columns.ToDictionary(column => column.Column, column => SqlServerTypeMapping.Map(column.DeclaredType), StringComparer.Ordinal),
                NullableColumns = nullable,
                IdentityColumns = [.. tableColumns.Where(column => column.Identity).Select(column => column.Column)],
                Identities = [.. tableColumns.Where(column => column.Identity).Select(column => new IdentityCopyPlan(
                    column.Column,
                    column.IdentitySeed,
                    column.IdentityIncrement,
                    column.IdentityCurrent ?? column.IdentitySeed,
                    column.IdentityCurrent.HasValue))],
                PrimaryKey = primaryKey,
                UniqueConstraints = uniqueConstraints,
                Indexes = CreateIndexes(tableIndexes),
                ForeignKeys = CreateForeignKeys(tableForeignKeys),
                DefaultExpressions = tableColumns
                    .Where(column => !string.IsNullOrWhiteSpace(column.DefaultExpression) && string.IsNullOrWhiteSpace(column.ComputedExpression))
                    .ToDictionary(column => column.Column, column => TranslateExpression(column.DefaultExpression), StringComparer.Ordinal),
                GeneratedColumns = [.. tableColumns
                    .Where(column => !string.IsNullOrWhiteSpace(column.ComputedExpression))
                    .Select(column => new GeneratedColumnCopyPlan(column.Column, TranslateExpression(column.ComputedExpression)))],
                CheckConstraints = [.. tableChecks.Select(check => new CheckConstraintCopyPlan(check.Name, TranslateExpression(check.Expression))
                {
                    Columns = inventory.OrderedColumns,
                })],
            };
            tables.Add(table);
        }

        var draft = new DatabaseSchemaPlan(database, "1.0", schema.SchemaSha256, new string('0', 64), tables);
        return draft with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft) };
    }

    private static async Task<IReadOnlyDictionary<(string, string), ColumnDetails[]>> ReadColumnDetailsAsync(
        SnapshotLease lease,
        CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT s.name, t.name, c.column_id, c.name, c.is_nullable, c.is_identity,
                   TRY_CONVERT(bigint, ic.seed_value), TRY_CONVERT(bigint, ic.increment_value), TRY_CONVERT(bigint, ic.last_value),
                   COALESCE(dc.definition, N''), COALESCE(cc.definition, N'')
            FROM sys.tables t
            JOIN sys.schemas s ON s.schema_id=t.schema_id
            JOIN sys.columns c ON c.object_id=t.object_id
            LEFT JOIN sys.identity_columns ic ON ic.object_id=c.object_id AND ic.column_id=c.column_id
            LEFT JOIN sys.default_constraints dc ON dc.object_id=c.default_object_id
            LEFT JOIN sys.computed_columns cc ON cc.object_id=c.object_id AND cc.column_id=c.column_id
            WHERE t.is_ms_shipped=0 ORDER BY s.name,t.name,c.column_id;
            """;
        var rows = new List<ColumnDetails>();
        await using var command = new SqlCommand(sql, lease.Connection, lease.Transaction);
        await using SqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            rows.Add(new(
                reader.GetString(0), reader.GetString(1), reader.GetInt32(2), reader.GetString(3), reader.GetBoolean(4), reader.GetBoolean(5),
                reader.IsDBNull(6) ? 0 : reader.GetInt64(6), reader.IsDBNull(7) ? 0 : reader.GetInt64(7), reader.IsDBNull(8) ? null : reader.GetInt64(8),
                reader.GetString(9), reader.GetString(10)));
        }
        return rows.GroupBy(row => (row.Schema, row.Table)).ToDictionary(group => group.Key, group => group.OrderBy(row => row.Ordinal).ToArray());
    }

    private static async Task<IReadOnlyDictionary<(string, string), IndexDetails[]>> ReadIndexDetailsAsync(
        SnapshotLease lease,
        CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT s.name,t.name,i.name,i.is_primary_key,i.is_unique_constraint,i.is_unique,
                   ic.key_ordinal,ic.index_column_id,c.name,ic.is_descending_key,ic.is_included_column,
                   COALESCE(i.filter_definition,N'')
            FROM sys.indexes i JOIN sys.tables t ON t.object_id=i.object_id JOIN sys.schemas s ON s.schema_id=t.schema_id
            JOIN sys.index_columns ic ON ic.object_id=i.object_id AND ic.index_id=i.index_id
            JOIN sys.columns c ON c.object_id=ic.object_id AND c.column_id=ic.column_id
            WHERE t.is_ms_shipped=0 AND i.is_hypothetical=0 AND i.name IS NOT NULL
            ORDER BY s.name,t.name,i.name,ic.key_ordinal,ic.index_column_id;
            """;
        var rows = new List<IndexRow>();
        await using var command = new SqlCommand(sql, lease.Connection, lease.Transaction);
        await using SqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            rows.Add(new(reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetBoolean(3), reader.GetBoolean(4), reader.GetBoolean(5),
                Convert.ToInt32(reader.GetValue(6), CultureInfo.InvariantCulture),
                Convert.ToInt32(reader.GetValue(7), CultureInfo.InvariantCulture),
                reader.GetString(8), reader.GetBoolean(9), reader.GetBoolean(10), reader.GetString(11)));
        }
        return rows.GroupBy(row => (row.Schema, row.Table, row.Name))
            .Select(group => new IndexDetails(group.Key.Schema, group.Key.Table, group.Key.Name, group.First().PrimaryKey,
                group.First().UniqueConstraint, group.First().Unique,
                [.. group.Where(row => !row.Included).OrderBy(row => row.KeyOrdinal).ThenBy(row => row.IndexOrdinal).Select(row => row.Column)],
                [.. group.Where(row => !row.Included && row.Descending).Select(row => row.Column)],
                [.. group.Where(row => row.Included).OrderBy(row => row.IndexOrdinal).Select(row => row.Column)], group.First().Filter))
            .GroupBy(row => (row.Schema, row.Table)).ToDictionary(group => group.Key, group => group.ToArray());
    }

    private static async Task<IReadOnlyDictionary<(string, string), ForeignKeyDetails[]>> ReadForeignKeyDetailsAsync(
        SnapshotLease lease,
        CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT cs.name,ct.name,fk.name,fkc.constraint_column_id,cc.name,rs.name,rt.name,rc.name,
                   fk.delete_referential_action,fk.update_referential_action,fk.is_disabled,fk.is_not_trusted
            FROM sys.foreign_keys fk JOIN sys.tables ct ON ct.object_id=fk.parent_object_id JOIN sys.schemas cs ON cs.schema_id=ct.schema_id
            JOIN sys.tables rt ON rt.object_id=fk.referenced_object_id JOIN sys.schemas rs ON rs.schema_id=rt.schema_id
            JOIN sys.foreign_key_columns fkc ON fkc.constraint_object_id=fk.object_id
            JOIN sys.columns cc ON cc.object_id=fkc.parent_object_id AND cc.column_id=fkc.parent_column_id
            JOIN sys.columns rc ON rc.object_id=fkc.referenced_object_id AND rc.column_id=fkc.referenced_column_id
            WHERE ct.is_ms_shipped=0 ORDER BY cs.name,ct.name,fk.name,fkc.constraint_column_id;
            """;
        var rows = new List<ForeignKeyRow>();
        await using var command = new SqlCommand(sql, lease.Connection, lease.Transaction);
        await using SqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            rows.Add(new(reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetInt32(3), reader.GetString(4), reader.GetString(5),
                reader.GetString(6), reader.GetString(7), reader.GetByte(8), reader.GetByte(9), reader.GetBoolean(10), reader.GetBoolean(11)));
        }
        return rows.GroupBy(row => (row.Schema, row.Table, row.Name))
            .Select(group => new ForeignKeyDetails(group.Key.Schema, group.Key.Table, group.Key.Name,
                [.. group.OrderBy(row => row.Ordinal).Select(row => row.Column)], group.First().ReferencedSchema, group.First().ReferencedTable,
                [.. group.OrderBy(row => row.Ordinal).Select(row => row.ReferencedColumn)], group.First().DeleteAction, group.First().UpdateAction,
                !group.First().Disabled, !group.First().NotTrusted))
            .GroupBy(row => (row.Schema, row.Table)).ToDictionary(group => group.Key, group => group.ToArray());
    }

    private static async Task<IReadOnlyDictionary<(string, string), CheckDetails[]>> ReadCheckDetailsAsync(
        SnapshotLease lease,
        CancellationToken cancellationToken)
    {
        const string sql = "SELECT s.name,t.name,cc.name,cc.definition,cc.is_disabled,cc.is_not_trusted FROM sys.check_constraints cc JOIN sys.tables t ON t.object_id=cc.parent_object_id JOIN sys.schemas s ON s.schema_id=t.schema_id WHERE t.is_ms_shipped=0 ORDER BY s.name,t.name,cc.name;";
        var rows = new List<CheckDetails>();
        await using var command = new SqlCommand(sql, lease.Connection, lease.Transaction);
        await using SqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            if (reader.GetBoolean(4) || reader.GetBoolean(5))
            {
                throw new MigrationExecutionException("source_check_constraint_untrusted", "Disabled or untrusted source checks are unsupported.");
            }
            rows.Add(new(reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3)));
        }
        return rows.GroupBy(row => (row.Schema, row.Table)).ToDictionary(group => group.Key, group => group.ToArray());
    }

    private static PrimaryKeyCopyPlan? CreatePrimaryKey(IEnumerable<IndexDetails> indexes)
    {
        return indexes.Where(index => index.PrimaryKey).Select(index => new PrimaryKeyCopyPlan(index.Name, index.Columns)).SingleOrDefault();
    }

    private static UniqueConstraintCopyPlan[] CreateUniqueConstraints(IEnumerable<IndexDetails> indexes)
    {
        return [.. indexes.Where(index => index.UniqueConstraint).Select(index => new UniqueConstraintCopyPlan(index.Name, index.Columns))];
    }

    private static IndexCopyPlan[] CreateIndexes(IEnumerable<IndexDetails> indexes)
    {
        return [.. indexes.Where(index => !index.PrimaryKey && !index.UniqueConstraint).Select(index => new IndexCopyPlan(index.Name, index.Columns, index.Unique)
        {
            DescendingColumns = index.DescendingColumns,
            IncludedColumns = index.IncludedColumns,
            FilterPredicate = string.IsNullOrWhiteSpace(index.Filter) ? null : TranslateExpression(index.Filter),
        })];
    }

    private static ForeignKeyCopyPlan[] CreateForeignKeys(IEnumerable<ForeignKeyDetails> keys)
    {
        return [.. keys.Select(key => key.Enabled && key.Trusted
            ? new ForeignKeyCopyPlan(key.Name, key.Columns, TargetSchema(key.ReferencedSchema), key.ReferencedTable, key.ReferencedColumns)
            {
                SourceReferencedSchema = key.ReferencedSchema,
                SourceReferencedTable = key.ReferencedTable,
                SourceReferencedColumns = key.ReferencedColumns,
                OnDelete = (ReferentialAction)key.DeleteAction,
                OnUpdate = (ReferentialAction)key.UpdateAction,
            }
            : throw new MigrationExecutionException("source_foreign_key_untrusted", "Disabled or untrusted source foreign keys are unsupported."))];
    }

    private static string TargetSchema(string sourceSchema)
    {
        return string.Equals(sourceSchema, "dbo", StringComparison.Ordinal) ? "public" : sourceSchema;
    }

    private static string TranslateExpression(string expression)
    {
        string translated = BracketedIdentifier().Replace(expression, match => $"\"{match.Groups[1].Value.Replace("\"", "\"\"", StringComparison.Ordinal)}\"")
            .Replace("getdate()", "CURRENT_TIMESTAMP", StringComparison.OrdinalIgnoreCase)
            .Replace("sysdatetime()", "CURRENT_TIMESTAMP", StringComparison.OrdinalIgnoreCase)
            .Replace("newid()", "gen_random_uuid()", StringComparison.OrdinalIgnoreCase)
            .Replace("newsequentialid()", "gen_random_uuid()", StringComparison.OrdinalIgnoreCase);
        return UnicodeStringPrefix().Replace(translated, "'");
    }

    [GeneratedRegex("\\[([^]\\0]+)\\]", RegexOptions.CultureInvariant)]
    private static partial Regex BracketedIdentifier();

    [GeneratedRegex("(?<![A-Za-z0-9_])N'", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UnicodeStringPrefix();

    private sealed record ColumnDetails(string Schema, string Table, int Ordinal, string Column, bool Nullable, bool Identity,
        long IdentitySeed, long IdentityIncrement, long? IdentityCurrent, string DefaultExpression, string ComputedExpression);
    private sealed record IndexRow(string Schema, string Table, string Name, bool PrimaryKey, bool UniqueConstraint, bool Unique,
        int KeyOrdinal, int IndexOrdinal, string Column, bool Descending, bool Included, string Filter);
    private sealed record IndexDetails(string Schema, string Table, string Name, bool PrimaryKey, bool UniqueConstraint, bool Unique,
        IReadOnlyList<string> Columns, IReadOnlyList<string> DescendingColumns, IReadOnlyList<string> IncludedColumns, string Filter);
    private sealed record ForeignKeyRow(string Schema, string Table, string Name, int Ordinal, string Column, string ReferencedSchema,
        string ReferencedTable, string ReferencedColumn, byte DeleteAction, byte UpdateAction, bool Disabled, bool NotTrusted);
    private sealed record ForeignKeyDetails(string Schema, string Table, string Name, IReadOnlyList<string> Columns, string ReferencedSchema,
        string ReferencedTable, IReadOnlyList<string> ReferencedColumns, byte DeleteAction, byte UpdateAction, bool Enabled, bool Trusted);
    private sealed record CheckDetails(string Schema, string Table, string Name, string Expression);
}

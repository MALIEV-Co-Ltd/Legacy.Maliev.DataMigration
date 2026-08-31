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
            IReadOnlyList<string>? ordering = primaryKey?.Columns ?? uniqueConstraints
                .FirstOrDefault(unique => !unique.Columns.Intersect(nullable, StringComparer.Ordinal).Any())?.Columns;
            bool sourceKnownEmpty = false;
            if (ordering is null)
            {
                sourceKnownEmpty = await IsTableEmptyAsync(lease, inventory, cancellationToken).ConfigureAwait(false);
                ordering = sourceKnownEmpty
                    ? inventory.OrderedColumns
                    : throw new MigrationExecutionException(
                        "source_table_total_order_missing",
                        "Every non-empty source table requires a non-null unique ordering key.");
            }
            string targetSchema = TargetSchema(inventory.SourceSchema);
            IReadOnlyDictionary<string, string> targetColumnTypes = inventory.Columns.ToDictionary(
                column => column.Column,
                column => SqlServerTypeMapping.Map(column.DeclaredType),
                StringComparer.Ordinal);
            IReadOnlyDictionary<string, string> sourceColumnTypes = inventory.Columns.ToDictionary(
                column => column.Column,
                column => column.DeclaredType,
                StringComparer.Ordinal);
            var table = new TableCopyPlan(
                inventory.SourceSchema,
                inventory.SourceTable,
                targetSchema,
                inventory.SourceTable,
                inventory.OrderedColumns,
                ordering)
            {
                SourceKnownEmpty = sourceKnownEmpty,
                SourceColumnTypes = sourceColumnTypes,
                SourceColumns = inventory.Columns,
                ColumnTypes = targetColumnTypes,
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
                    .ToDictionary(column => column.Column, column => TranslateExpressionForPostgreSql(column.DefaultExpression), StringComparer.Ordinal),
                GeneratedColumns = [.. tableColumns
                    .Where(column => !string.IsNullOrWhiteSpace(column.ComputedExpression))
                    .Select(column => new GeneratedColumnCopyPlan(
                        column.Column,
                        TranslateGeneratedExpressionForPostgreSql(
                            column.ComputedExpression,
                            sourceColumnTypes,
                            targetColumnTypes)))],
                CheckConstraints = [.. tableChecks.Select(check => new CheckConstraintCopyPlan(check.Name, TranslateExpressionForPostgreSql(check.Expression))
                {
                    Columns = inventory.OrderedColumns,
                })],
            };
            tables.Add(table);
        }

        var draft = new DatabaseSchemaPlan(database, "1.0", schema.SchemaSha256, new string('0', 64), tables);
        return draft with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft) };
    }

    private static async Task<bool> IsTableEmptyAsync(
        SnapshotLease lease,
        SourceTableInventory table,
        CancellationToken cancellationToken)
    {
        string sql = $"SELECT CASE WHEN EXISTS (SELECT TOP (1) 1 FROM {QuoteIdentifier(table.SourceSchema)}.{QuoteIdentifier(table.SourceTable)}) THEN 0 ELSE 1 END;";
        await using var command = new SqlCommand(sql, lease.Connection, lease.Transaction);
        object? result = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        return Convert.ToInt32(result, CultureInfo.InvariantCulture) == 1;
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
            FilterPredicate = string.IsNullOrWhiteSpace(index.Filter) ? null : TranslateExpressionForPostgreSql(index.Filter),
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

    internal static string TranslateExpressionForPostgreSql(string expression)
    {
        string translated = BracketedIdentifier().Replace(expression, match => $"\"{match.Groups[1].Value.Replace("\"", "\"\"", StringComparison.Ordinal)}\"")
            .Replace("getutcdate()", "timezone('UTC'::text, CURRENT_TIMESTAMP)", StringComparison.OrdinalIgnoreCase)
            .Replace("getdate()", "CURRENT_TIMESTAMP", StringComparison.OrdinalIgnoreCase)
            .Replace("sysdatetime()", "CURRENT_TIMESTAMP", StringComparison.OrdinalIgnoreCase)
            .Replace("newid()", "gen_random_uuid()", StringComparison.OrdinalIgnoreCase)
            .Replace("newsequentialid()", "gen_random_uuid()", StringComparison.OrdinalIgnoreCase);
        return UnicodeStringPrefix().Replace(translated, "'");
    }

    internal static string TranslateGeneratedExpressionForPostgreSql(
        string expression,
        IReadOnlyDictionary<string, string> sourceColumnTypes,
        IReadOnlyDictionary<string, string> targetColumnTypes)
    {
        ArgumentNullException.ThrowIfNull(sourceColumnTypes);
        ArgumentNullException.ThrowIfNull(targetColumnTypes);
        if (VolatileGeneratedExpression().IsMatch(expression))
        {
            throw new MigrationExecutionException(
                "source_computed_expression_volatile",
                "Volatile SQL Server computed expressions cannot be represented by immutable PostgreSQL generated columns.");
        }

        string translated = TranslateExpressionForPostgreSql(expression);
        Match trimConcat = TrimConcatGeneratedColumn().Match(translated);
        if (trimConcat.Success)
        {
            string first = trimConcat.Groups["first"].Value;
            string last = trimConcat.Groups["last"].Value;
            _ = GetColumnType(first, targetColumnTypes).StartsWith("character varying", StringComparison.Ordinal) &&
                GetColumnType(last, targetColumnTypes).StartsWith("character varying", StringComparison.Ordinal)
                ? true
                : throw new MigrationExecutionException(
                    "source_computed_text_type_unsupported",
                    "The SQL Server CONCAT computed expression requires character-varying source columns.");
            return $"btrim((((COALESCE({first}, ''::character varying))::text || ' '::text) || (COALESCE({last}, ''::character varying))::text))";
        }

        Match decimalConvert = DecimalConvertGeneratedColumn().Match(translated);
        if (decimalConvert.Success)
        {
            return TranslateDecimalGeneratedExpression(
                decimalConvert.Groups["value"].Value,
                decimalConvert.Groups["precision"].Value,
                decimalConvert.Groups["scale"].Value,
                targetColumnTypes);
        }

        Match dateDiff = DateDiffDayGeneratedColumn().Match(translated);
        if (dateDiff.Success)
        {
            string start = DateOperand(dateDiff.Groups["start"].Value, sourceColumnTypes, targetColumnTypes);
            string end = DateOperand(dateDiff.Groups["end"].Value, sourceColumnTypes, targetColumnTypes);
            return $"({end} - {start})";
        }

        Match arithmetic = BinaryArithmeticGeneratedColumn().Match(translated);
        if (arithmetic.Success)
        {
            _ = NumericOperand(arithmetic.Groups["left"].Value, targetColumnTypes);
            _ = NumericOperand(arithmetic.Groups["right"].Value, targetColumnTypes);
            _ = GetColumnType(arithmetic.Groups["left"].Value, sourceColumnTypes);
            _ = GetColumnType(arithmetic.Groups["right"].Value, sourceColumnTypes);
            return $"({arithmetic.Groups["left"].Value} {arithmetic.Groups["operator"].Value} {arithmetic.Groups["right"].Value})";
        }

        throw new MigrationExecutionException(
            "source_computed_expression_unsupported",
            "A SQL Server computed expression is outside the approved immutable PostgreSQL translation set.");
    }

    private static string TranslateDecimalGeneratedExpression(
        string value,
        string precision,
        string scale,
        IReadOnlyDictionary<string, string> targetColumnTypes)
    {
        Match multiplication = NumericMultiplication().Match(value);
        if (multiplication.Success)
        {
            NumericTerm left = NumericOperand(multiplication.Groups["left"].Value, targetColumnTypes);
            NumericTerm right = NumericOperand(multiplication.Groups["right"].Value, targetColumnTypes);
            DecimalShape product = Multiply(left.Shape, right.Shape);
            string valueAtSourcePrecision = CastNumeric($"({left.Expression} * {right.Expression})", product);
            return CastNumeric(valueAtSourcePrecision, ParseShape(precision, scale));
        }

        Match subtraction = NumericSubtraction().Match(value);
        if (subtraction.Success)
        {
            NumericTerm left = NumericOperand(subtraction.Groups["left"].Value, targetColumnTypes);
            NumericTerm right = NumericOperand(subtraction.Groups["right"].Value, targetColumnTypes);
            DecimalShape difference = AddOrSubtract(left.Shape, right.Shape);
            string valueAtSourcePrecision = CastNumeric($"({left.Expression} - {right.Expression})", difference);
            return CastNumeric(valueAtSourcePrecision, ParseShape(precision, scale));
        }

        Match discounted = DiscountedSubtotal().Match(value);
        if (discounted.Success &&
            string.Equals(discounted.Groups["price"].Value, discounted.Groups["priceAgain"].Value, StringComparison.Ordinal) &&
            string.Equals(discounted.Groups["quantity"].Value, discounted.Groups["quantityAgain"].Value, StringComparison.Ordinal))
        {
            NumericTerm price = NumericOperand(discounted.Groups["price"].Value, targetColumnTypes);
            NumericTerm quantity = NumericOperand(discounted.Groups["quantity"].Value, targetColumnTypes);
            NumericTerm discount = NumericOperand(discounted.Groups["discount"].Value, targetColumnTypes);
            var integerLiteral = new NumericTerm("(100)::numeric", new(10, 0));
            DecimalShape grossShape = Multiply(price.Shape, quantity.Shape);
            string gross = CastNumeric($"({price.Expression} * {quantity.Expression})", grossShape);
            DecimalShape discountAmountShape = Multiply(grossShape, discount.Shape);
            string discountAmount = CastNumeric($"({gross} * {discount.Expression})", discountAmountShape);
            DecimalShape discountedShape = Divide(discountAmountShape, integerLiteral.Shape);
            string discountedAmount = CastNumeric($"({discountAmount} / {integerLiteral.Expression})", discountedShape);
            DecimalShape subtotalShape = AddOrSubtract(grossShape, discountedShape);
            string subtotal = CastNumeric($"({gross} - {discountedAmount})", subtotalShape);
            return CastNumeric(subtotal, ParseShape(precision, scale));
        }

        throw new MigrationExecutionException(
            "source_computed_decimal_unsupported",
            "A SQL Server decimal computed expression cannot be translated safely to PostgreSQL.");
    }

    private static NumericTerm NumericOperand(
        string quotedIdentifier,
        IReadOnlyDictionary<string, string> targetColumnTypes)
    {
        string type = GetColumnType(quotedIdentifier, targetColumnTypes);

        return type switch
        {
            "smallint" => new($"({quotedIdentifier})::numeric", new(5, 0)),
            "integer" => new($"({quotedIdentifier})::numeric", new(10, 0)),
            "bigint" => new($"({quotedIdentifier})::numeric", new(19, 0)),
            _ when NumericType().Match(type) is { Success: true } numeric => new(
                quotedIdentifier,
                ParseShape(numeric.Groups["precision"].Value, numeric.Groups["scale"].Value)),
            _ => throw new MigrationExecutionException(
                "source_computed_numeric_type_unsupported",
                "A SQL Server decimal computed expression references a non-numeric source column."),
        };
    }

    private static DecimalShape ParseShape(string precision, string scale)
    {
        return new(
            int.Parse(precision, NumberStyles.None, CultureInfo.InvariantCulture),
            int.Parse(scale, NumberStyles.None, CultureInfo.InvariantCulture));
    }

    private static DecimalShape Multiply(DecimalShape left, DecimalShape right)
    {
        return Reduce(left.Precision + right.Precision + 1, left.Scale + right.Scale);
    }

    private static DecimalShape Divide(DecimalShape left, DecimalShape right)
    {
        int scale = Math.Max(6, left.Scale + right.Precision + 1);
        int precision = left.Precision - left.Scale + right.Scale + scale;
        return Reduce(precision, scale);
    }

    private static DecimalShape AddOrSubtract(DecimalShape left, DecimalShape right)
    {
        int scale = Math.Max(left.Scale, right.Scale);
        int integral = Math.Max(left.Precision - left.Scale, right.Precision - right.Scale) + 1;
        int precision = integral + scale;
        return precision <= 38
            ? new(precision, scale)
            : new(38, Math.Min(scale, 38 - integral));
    }

    private static DecimalShape Reduce(int precision, int scale)
    {
        if (precision <= 38)
        {
            return new(precision, scale);
        }

        int integral = precision - scale;
        int reducedScale = integral < 32
            ? Math.Min(scale, 38 - integral)
            : scale > 6 ? 6 : scale;
        return new(38, reducedScale);
    }

    private static string CastNumeric(string expression, DecimalShape shape)
    {
        return $"({expression})::numeric({shape.Precision},{shape.Scale})";
    }

    private static string DateOperand(
        string quotedIdentifier,
        IReadOnlyDictionary<string, string> sourceColumnTypes,
        IReadOnlyDictionary<string, string> targetColumnTypes)
    {
        string sourceType = GetColumnType(quotedIdentifier, sourceColumnTypes).Trim().ToLowerInvariant();
        string targetType = GetColumnType(quotedIdentifier, targetColumnTypes);
        return !SqlServerTemporalType().IsMatch(sourceType)
            ? throw new MigrationExecutionException(
                "source_computed_temporal_type_unsupported",
                "A SQL Server DATEDIFF computed expression references an unsupported temporal source column.")
            : (sourceType, targetType) switch
            {
                ("date", "date") => quotedIdentifier,
                (_, "timestamp without time zone") when LosslessSqlServerTimestampType().IsMatch(sourceType) =>
                    $"({quotedIdentifier})::date",
                _ => throw new MigrationExecutionException(
                    "source_computed_temporal_mapping_unproven",
                    "A SQL Server DATEDIFF computed expression requires an approved lossless source-to-target temporal mapping."),
            };
    }

    private static string GetColumnType(
        string quotedIdentifier,
        IReadOnlyDictionary<string, string> targetColumnTypes)
    {
        string column = quotedIdentifier[1..^1].Replace("\"\"", "\"", StringComparison.Ordinal);
        return targetColumnTypes.TryGetValue(column, out string? mappedType)
            ? mappedType
            : throw new MigrationExecutionException(
                "source_computed_column_missing",
                "A computed expression references a column outside the source schema plan.");
    }

    [GeneratedRegex("\\[([^]\\0]+)\\]", RegexOptions.CultureInvariant)]
    private static partial Regex BracketedIdentifier();

    [GeneratedRegex("(?<![A-Za-z0-9_])N'", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UnicodeStringPrefix();

    [GeneratedRegex("\\b(?:CURRENT_TIMESTAMP|GETDATE|GETUTCDATE|SYSDATETIME|SYSUTCDATETIME|SYSDATETIMEOFFSET|NEWID|NEWSEQUENTIALID|RAND)\\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex VolatileGeneratedExpression();

    [GeneratedRegex("^\\(Trim\\(concat\\((?<first>\"(?:[^\"]|\"\")+\"),' ',(?<last>\"(?:[^\"]|\"\")+\")\\)\\)\\)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex TrimConcatGeneratedColumn();

    [GeneratedRegex("^\\(CONVERT\\(\"decimal\"\\((?<precision>[0-9]+),(?<scale>[0-9]+)\\),(?<value>.+)\\)\\)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex DecimalConvertGeneratedColumn();

    [GeneratedRegex("^\\(datediff\\(day,(?<start>\"(?:[^\"]|\"\")+\"),(?<end>\"(?:[^\"]|\"\")+\")\\)\\)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex DateDiffDayGeneratedColumn();

    [GeneratedRegex("^\\((?<left>\"(?:[^\"]|\"\")+\")(?<operator>[-+])(?<right>\"(?:[^\"]|\"\")+\")\\)$", RegexOptions.CultureInvariant)]
    private static partial Regex BinaryArithmeticGeneratedColumn();

    [GeneratedRegex("^(?<left>\"(?:[^\"]|\"\")+\")\\*(?<right>\"(?:[^\"]|\"\")+\")$", RegexOptions.CultureInvariant)]
    private static partial Regex NumericMultiplication();

    [GeneratedRegex("^(?<left>\"(?:[^\"]|\"\")+\")-(?<right>\"(?:[^\"]|\"\")+\")$", RegexOptions.CultureInvariant)]
    private static partial Regex NumericSubtraction();

    [GeneratedRegex("^(?<price>\"(?:[^\"]|\"\")+\")\\*(?<quantity>\"(?:[^\"]|\"\")+\")-\\(\\((?<priceAgain>\"(?:[^\"]|\"\")+\")\\*(?<quantityAgain>\"(?:[^\"]|\"\")+\")\\)\\*(?<discount>\"(?:[^\"]|\"\")+\")\\)/\\(100\\)$", RegexOptions.CultureInvariant)]
    private static partial Regex DiscountedSubtotal();

    [GeneratedRegex("^numeric\\((?<precision>[0-9]+),(?<scale>[0-9]+)\\)$", RegexOptions.CultureInvariant)]
    private static partial Regex NumericType();

    [GeneratedRegex("^(?:date|datetime|smalldatetime|datetime2\\([0-7]\\)|datetimeoffset(?:\\([0-7]\\))?)$", RegexOptions.CultureInvariant)]
    private static partial Regex SqlServerTemporalType();

    [GeneratedRegex("^(?:datetime|smalldatetime|datetime2\\([0-6]\\))$", RegexOptions.CultureInvariant)]
    private static partial Regex LosslessSqlServerTimestampType();

    private readonly record struct DecimalShape(int Precision, int Scale);

    private readonly record struct NumericTerm(string Expression, DecimalShape Shape);

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

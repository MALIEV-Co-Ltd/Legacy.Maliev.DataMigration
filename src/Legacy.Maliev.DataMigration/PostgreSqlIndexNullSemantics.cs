namespace Legacy.Maliev.DataMigration;

internal static class PostgreSqlIndexNullSemantics
{
    internal static bool RequiresNullsNotDistinct(IndexCopyPlan index, TableCopyPlan table)
    {
        if (!index.Unique || !index.Columns.Intersect(table.NullableColumns, StringComparer.Ordinal).Any())
        {
            return false;
        }

        // A single nullable key is never NULL in this partial index, so either
        // PostgreSQL NULLS setting enforces the same SQL Server uniqueness rule.
        string trimmed = index.FilterPredicate?.Trim() ?? string.Empty;
        return index.Columns.Count != 1 ||
            (trimmed != $"(\"{index.Columns[0]}\" IS NOT NULL)" &&
             trimmed != $"\"{index.Columns[0]}\" IS NOT NULL");
    }
}

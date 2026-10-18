using System.Data;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal static class CurrentCustomerClosedRows
{
    private static readonly string[] Names = ["ID", "FirstName", "LastName", "FullName", "Telephone", "Mobile", "Fax", "Email", "DateOfBirth",
        "CompanyID", "BillingAddressID", "ShippingAddressID", "CreatedDate", "ModifiedDate", "Notes"];
    // Reviewed metadata reference: source-catalog-readonly-20261013-e5f.../report.json,
    // Customer.dbo.Customer. Runtime requires the genuine plan, not this comment.
    internal static async Task PopulateBeforeCaptureAsync(CurrentCustomerClosedTemplateState state, FreshSchemaPlan source,
        string adminConnection, CancellationToken ct)
    {
        CurrentCustomerSequenceCapacity.Require(admission: false);
        var table = source.Databases.Single(x => x.Database == "Customer").Tables.Single(x => x.TargetSchema == "public" && x.TargetTable == "Customer");
        if (state.ExpiresAtUtc <= DateTimeOffset.UtcNow || table.SourceSchema != "dbo" || table.SourceTable != "Customer" ||
            !table.OrderedColumns.SequenceEqual(Names, StringComparer.Ordinal) || !table.IdentityColumns.SequenceEqual(["ID"], StringComparer.Ordinal) ||
            table.ColumnTypes["ID"] != "integer" || table.PrimaryKey is null || !table.PrimaryKey.Columns.SequenceEqual(["ID"], StringComparer.Ordinal) ||
            table.OrderedColumns.Except(["ID", "FirstName", "LastName", "Email"], StringComparer.Ordinal).Any(x =>
                !table.NullableColumns.Contains(x, StringComparer.Ordinal) && !table.GeneratedColumns.Any(y => y.Column == x)) ||
            table.GeneratedColumns.Any(x => x.Column != "FullName"))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        var endpoint = new NpgsqlConnectionStringBuilder(adminConnection) { Database = "Customer" };
        if (endpoint.Host != "127.0.0.1" || endpoint.Username != "postgres" || endpoint.Pooling || endpoint.SslMode != SslMode.Disable || !string.IsNullOrEmpty(endpoint.Options))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        using var lease = CancellationTokenSource.CreateLinkedTokenSource(ct); lease.CancelAfter(state.ExpiresAtUtc - DateTimeOffset.UtcNow);
        await using var connection = new NpgsqlConnection(endpoint.ConnectionString); await connection.OpenAsync(lease.Token).ConfigureAwait(false);
        await using var tx = await connection.BeginTransactionAsync(IsolationLevel.Serializable, lease.Token).ConfigureAwait(false);
        await using (var empty = new NpgsqlCommand("SELECT count(*) FROM public.\"Customer\";", connection, tx))
        { if (Convert.ToInt64(await empty.ExecuteScalarAsync(lease.Token).ConfigureAwait(false), System.Globalization.CultureInfo.InvariantCulture) != 0) { throw CurrentCustomerSequenceRepairPermit.Invalid(); } }
        string[] columns = Names.Where(x => !table.GeneratedColumns.Any(y => y.Column == x)).ToArray();
        string sql = "INSERT INTO public.\"Customer\" (" + string.Join(',', columns.Select(Q)) + ") VALUES (" +
            string.Join(',', columns.Select((_, i) => "@p" + i.ToString(System.Globalization.CultureInfo.InvariantCulture))) + ");";
        for (int row = 0; row < 2; row++)
        {
            await using var command = new NpgsqlCommand(sql, connection, tx);
            foreach ((string column, int ordinal) in columns.Select((name, index) => (name, index)))
            {
                object value = column switch
                {
                    "ID" => row == 0 ? 7 : 9,
                    "FirstName" => row == 0 ? "ข้อมูลทดสอบ" : "Fixture B",
                    "LastName" => row == 0 ? "รักษาไบต์" : "retained",
                    "FullName" => row == 0 ? "ข้อมูลทดสอบ รักษาไบต์" : "Fixture B retained",
                    "Email" => row == 0 ? "fixture-a@invalid.example" : "fixture-b@invalid.example",
                    "Notes" => row == 0 ? "ไทย trailing space " : "retained\nsecond line",
                    "CreatedDate" or "ModifiedDate" => new DateTime(2026, 10, 13, 0, 0, 0, DateTimeKind.Unspecified),
                    _ => DBNull.Value
                };
                var parameter = new NpgsqlParameter("p" + ordinal.ToString(System.Globalization.CultureInfo.InvariantCulture), value)
                {
                    NpgsqlDbType = table.ColumnTypes[column] switch
                    {
                        "integer" => NpgsqlTypes.NpgsqlDbType.Integer,
                        "date" => NpgsqlTypes.NpgsqlDbType.Date,
                        "timestamp without time zone" => NpgsqlTypes.NpgsqlDbType.Timestamp,
                        "text" => NpgsqlTypes.NpgsqlDbType.Text,
                        string type when type.StartsWith("character varying(", StringComparison.Ordinal) => NpgsqlTypes.NpgsqlDbType.Varchar,
                        _ => throw CurrentCustomerSequenceRepairPermit.Invalid()
                    }
                };
                _ = command.Parameters.Add(parameter);
            }
            if (await command.ExecuteNonQueryAsync(lease.Token).ConfigureAwait(false) != 1) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        }
        await using (var journal = new NpgsqlCommand("CREATE TABLE private.fixture_journal(id integer PRIMARY KEY,evidence text NOT NULL); INSERT INTO private.fixture_journal VALUES (1,'retained immutable journal'),(2,'ไทย');", connection, tx))
        { _ = await journal.ExecuteNonQueryAsync(lease.Token).ConfigureAwait(false); }
        await tx.CommitAsync(lease.Token).ConfigureAwait(false);
        await using var analyze = new NpgsqlCommand("ANALYZE public.\"Customer\";", connection);
        _ = await analyze.ExecuteNonQueryAsync(lease.Token).ConfigureAwait(false);         // Explicit IDs do not call setval or nextval: the already observed allocation
        // is retained. The actual provider alone changes START1 to START1000 later.
    }
    private static string Q(string value)
    {
        return "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    }
}

using Legacy.Maliev.DataMigration.Console;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class DeltaFailureClassificationTests
{
    [Fact]
    public void ClassifyDeltaFailure_ProviderError_DoesNotExposeExceptionMessage()
    {
        var failure = new NpgsqlException("sensitive connection detail");

        string code = MigrationConsole.ClassifyDeltaFailure(failure);

        Assert.Equal("delta_postgresql_connection_failed", code);
        Assert.DoesNotContain("sensitive", code, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("3D000", "delta_postgresql_database_missing")]
    [InlineData("42501", "delta_postgresql_permission_denied")]
    [InlineData("42P01", "delta_postgresql_relation_missing")]
    [InlineData("42703", "delta_postgresql_column_missing")]
    [InlineData("XX000", "delta_postgresql_query_failed")]
    public void ClassifyDeltaFailure_PostgresSqlState_ReturnsSafeCategory(string sqlState, string expected)
    {
        var failure = new PostgresException("sensitive detail", "ERROR", "ERROR", sqlState);

        Assert.Equal(expected, MigrationConsole.ClassifyDeltaFailure(failure));
    }

    [Fact]
    public void ClassifyDeltaFailure_RuntimeState_ReturnsSafeCategory()
    {
        Assert.Equal("delta_runtime_state_invalid",
            MigrationConsole.ClassifyDeltaFailure(new InvalidOperationException("sensitive detail")));
    }

    [Theory]
    [InlineData(-2, "delta_sqlserver_query_timeout")]
    [InlineData(207, "delta_sqlserver_column_missing")]
    [InlineData(208, "delta_sqlserver_relation_missing")]
    [InlineData(229, "delta_sqlserver_permission_denied")]
    [InlineData(1205, "delta_sqlserver_deadlock")]
    [InlineData(3960, "delta_sqlserver_snapshot_conflict")]
    [InlineData(4060, "delta_sqlserver_database_unavailable")]
    [InlineData(447, "delta_sqlserver_error_eeh")]
    [InlineData(-99999, "delta_sqlserver_query_failed")]
    public void ClassifySqlServerErrorNumber_ReturnsSafeCategory(int number, string expected)
    {
        Assert.Equal(expected, MigrationConsole.ClassifySqlServerErrorNumber(number));
    }
}

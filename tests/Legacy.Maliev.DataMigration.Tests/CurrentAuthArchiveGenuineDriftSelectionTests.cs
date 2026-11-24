namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveGenuineDriftSelectionTests
{
    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    [InlineData(10)]
    [InlineData(12)]
    [InlineData(13)]
    [InlineData(14)]
    public void Non_row_cases_refuse_row_selection_and_marker_with_the_guard_error(int number)
    {
        var value = (CurrentAuthArchiveGenuineExecutionCase)number;
        var row = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuineDrift.RowSql(value));
        var marker = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuineDrift.Marker(value));
        Assert.Equal("current_auth_archive_genuine_execution_invalid", row.Code);
        Assert.Equal("current_auth_archive_genuine_execution_invalid", marker.Code);
    }
}

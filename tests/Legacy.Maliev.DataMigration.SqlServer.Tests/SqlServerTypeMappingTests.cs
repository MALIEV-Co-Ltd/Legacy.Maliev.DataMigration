namespace Legacy.Maliev.DataMigration.Tests;

public sealed class SqlServerTypeMappingTests
{
    [Theory]
    [InlineData("int", "integer")]
    [InlineData("bigint", "bigint")]
    [InlineData("bit", "boolean")]
    [InlineData("uniqueidentifier", "uuid")]
    [InlineData("decimal(19,4)", "numeric(19,4)")]
    [InlineData("nvarchar(200)", "character varying(200)")]
    [InlineData("sysname", "character varying(128)")]
    [InlineData("nvarchar(max)", "text")]
    [InlineData("varbinary(max)", "bytea")]
    [InlineData("datetime2(6)", "timestamp without time zone")]
    [InlineData("datetime2(7)", "text")]
    [InlineData("datetimeoffset(7)", "text")]
    public void Map_PreservesSupportedSourceSemantics(string source, string expected)
    {
        Assert.Equal(expected, SqlServerTypeMapping.Map(source));
    }

    [Theory]
    [InlineData("sql_variant")]
    [InlineData("geography")]
    [InlineData("hierarchyid")]
    public void Map_UnsupportedSourceTypeFailsClosed(string source)
    {
        MigrationExecutionException exception = Assert.Throws<MigrationExecutionException>(() => SqlServerTypeMapping.Map(source));

        Assert.Equal("source_type_mapping_unsupported", exception.Code);
    }
}

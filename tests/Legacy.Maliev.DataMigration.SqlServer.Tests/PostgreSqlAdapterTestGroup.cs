namespace Legacy.Maliev.DataMigration.Tests;

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class SqlServerPostgreSqlAdapterTestGroup : ICollectionFixture<PostgreSqlAdapterFixture>
{
    public const string Name = PostgreSqlAdapterTestGroup.Name;
}

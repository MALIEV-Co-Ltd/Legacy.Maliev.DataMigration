using System.Reflection;
using System.Runtime.CompilerServices;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class SqlServerAdapterAssemblyDependencyTests
{
    [Fact]
    public void Adapter_owns_SQL_Client_and_implements_the_provider_neutral_factory()
    {
        Assembly adapter = typeof(SqlServerMigrationSource).Assembly;

        Assert.NotEqual(typeof(DeltaSynchronizationPlan).Assembly, adapter);
        Assert.Contains(adapter.GetReferencedAssemblies(), reference => reference.Name == "Microsoft.Data.SqlClient");
        _ = Assert.IsType<IMigrationSourceFactory>(new SqlServerMigrationSourceFactory(), exactMatch: false);
        _ = Assert.IsType<IRestoredMigrationSourceObserver>(
            new DockerSqlRestoredSourceObserver(new ReceiptAttestationTrustStore([])), exactMatch: false);
    }

    [Fact]
    public void Adapter_grants_internal_access_only_to_its_own_tests()
    {
        string[] friends = typeof(SqlServerMigrationSource).Assembly
            .GetCustomAttributes<InternalsVisibleToAttribute>()
            .Select(attribute => attribute.AssemblyName.Split(',')[0])
            .Order(StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(["Legacy.Maliev.DataMigration.SqlServer.Tests"], friends);
    }
}

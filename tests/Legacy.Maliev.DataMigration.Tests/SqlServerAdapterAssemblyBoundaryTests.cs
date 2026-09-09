using System.Reflection;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class SqlServerAdapterAssemblyBoundaryTests
{
    [Fact]
    public void Core_has_no_SQL_Client_dependency_or_provider_implementation_types()
    {
        Assembly core = typeof(DeltaSynchronizationPlan).Assembly;

        Assert.DoesNotContain(core.GetReferencedAssemblies(), reference => reference.Name == "Microsoft.Data.SqlClient");
        Assert.Null(core.GetType("Legacy.Maliev.DataMigration.SqlServerMigrationSource"));
        Assert.Null(core.GetType("Legacy.Maliev.DataMigration.DockerSqlRestoredSourceObserver"));
        Assert.Equal(core, typeof(IMigrationSourceFactory).Assembly);
        Assert.Equal(core, typeof(Exact23DeltaExecutionCoordinator).Assembly);
    }

    [Fact]
    public void Core_project_has_no_SQL_Client_package_and_console_references_adapter()
    {
        string root = Repository();
        string core = File.ReadAllText(Path.Combine(root, "src", "Legacy.Maliev.DataMigration", "Legacy.Maliev.DataMigration.csproj"));
        string console = File.ReadAllText(Path.Combine(root, "src", "Legacy.Maliev.DataMigration.Console", "Legacy.Maliev.DataMigration.Console.csproj"));

        Assert.DoesNotContain("Microsoft.Data.SqlClient", core, StringComparison.Ordinal);
        Assert.Contains("Legacy.Maliev.DataMigration.SqlServer.csproj", console, StringComparison.Ordinal);
    }

    [Fact]
    public void Core_test_project_has_no_SQL_Server_dependencies()
    {
        string root = Repository();
        string tests = File.ReadAllText(Path.Combine(
            root,
            "tests",
            "Legacy.Maliev.DataMigration.Tests",
            "Legacy.Maliev.DataMigration.Tests.csproj"));

        Assert.DoesNotContain("Testcontainers.MsSql", tests, StringComparison.Ordinal);
        Assert.DoesNotContain("Microsoft.Data.SqlClient", tests, StringComparison.Ordinal);
        Assert.DoesNotContain("Legacy.Maliev.DataMigration.SqlServer.csproj", tests, StringComparison.Ordinal);
    }

    private static string Repository()
    {
        for (DirectoryInfo? directory = new(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "Legacy.Maliev.DataMigration.slnx")))
            {
                return directory.FullName;
            }
        }
        throw new InvalidOperationException("Repository root not found.");
    }
}

using Legacy.Maliev.DataMigration.Console;

return await MigrationConsole.RunAsync(
    args,
    Console.Out,
    Console.Error,
    Environment.GetEnvironmentVariable,
    CancellationToken.None);

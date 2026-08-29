using Legacy.Maliev.DataMigration.Console;

try
{
    ConsoleInvocation invocation = ConsoleInvocation.Parse(args);
    Console.Error.WriteLine($"{invocation.Command}: host wiring is not yet configured.");
    return 2;
}
catch (CommandLineException exception)
{
    Console.Error.WriteLine(exception.Code);
    return 64;
}

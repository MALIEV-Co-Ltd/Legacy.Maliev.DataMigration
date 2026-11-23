namespace Legacy.Maliev.DataMigration.Console;

internal static class UncancelledTextWriterExtensions
{
    // Output remains non-cancellable and uses the writer's original virtual string overload.
    internal static Task WriteUncancelledAsync(this TextWriter writer, string? value) => writer.WriteAsync(value);

    internal static Task WriteLineUncancelledAsync(this TextWriter writer, string? value) => writer.WriteLineAsync(value);
}

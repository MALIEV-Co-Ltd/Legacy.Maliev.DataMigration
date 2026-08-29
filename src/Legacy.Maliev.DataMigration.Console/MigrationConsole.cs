using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Legacy.Maliev.DataMigration.Console;

public static class MigrationConsole
{
    private const string SigningKeyEnvironmentVariable = "LEGACY_MIGRATION_RECEIPT_SIGNING_KEY_FILE";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    public static async Task<int> RunAsync(
        IReadOnlyList<string> arguments,
        TextWriter output,
        TextWriter error,
        Func<string, string?> getEnvironmentVariable,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);
        ArgumentNullException.ThrowIfNull(getEnvironmentVariable);
        try
        {
            ConsoleInvocation invocation = ConsoleInvocation.Parse(arguments);
            if (!string.Equals(invocation.Command, "receipt", StringComparison.Ordinal))
            {
                await error.WriteLineAsync("stage_not_configured").ConfigureAwait(false);
                return 2;
            }

            await ProduceReceiptAsync(invocation.ConfigPath, getEnvironmentVariable, cancellationToken).ConfigureAwait(false);
            await output.WriteLineAsync("receipt_complete").ConfigureAwait(false);
            return 0;
        }
        catch (CommandLineException exception)
        {
            await error.WriteLineAsync(exception.Code).ConfigureAwait(false);
            return 64;
        }
        catch (MigrationConsoleException exception)
        {
            await error.WriteLineAsync(exception.Code).ConfigureAwait(false);
            return 65;
        }
        catch (BackupReceiptProductionException exception)
        {
            await error.WriteLineAsync(exception.Code).ConfigureAwait(false);
            return 65;
        }
    }

    private static async Task ProduceReceiptAsync(
        string configPath,
        Func<string, string?> getEnvironmentVariable,
        CancellationToken cancellationToken)
    {
        MigrationConsoleConfiguration configuration = await ReadJsonAsync<MigrationConsoleConfiguration>(configPath, cancellationToken)
            .ConfigureAwait(false);
        ReceiptCommandConfiguration receipt = configuration.Receipt ??
            throw new MigrationConsoleException("receipt_configuration_missing", "Receipt configuration is required.");
        string keyPath = getEnvironmentVariable(SigningKeyEnvironmentVariable) ??
            throw new MigrationConsoleException("receipt_signing_key_reference_missing", "The signing key file reference is required.");
        BackupStateDocument state = await ReadJsonAsync<BackupStateDocument>(receipt.BackupStatePath, cancellationToken)
            .ConfigureAwait(false);

        using ECDsa key = ECDsa.Create();
        try
        {
            key.ImportFromPem(await File.ReadAllTextAsync(keyPath, cancellationToken).ConfigureAwait(false));
        }
        catch (CryptographicException)
        {
            throw new MigrationConsoleException("receipt_signing_key_invalid", "The signing key file is invalid.");
        }

        BackupReceipt backupReceipt = await BackupReceiptProducer.ProduceAsync(
            state.Artifacts,
            receipt.KeyId,
            key,
            DateTimeOffset.UtcNow,
            cancellationToken).ConfigureAwait(false);
        await WriteNewJsonAsync(receipt.OutputPath, backupReceipt, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<T> ReadJsonAsync<T>(string path, CancellationToken cancellationToken)
    {
        try
        {
            await using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            return await JsonSerializer.DeserializeAsync<T>(stream, JsonOptions, cancellationToken).ConfigureAwait(false) ??
                throw new MigrationConsoleException("configuration_invalid", "A referenced JSON document is empty.");
        }
        catch (JsonException)
        {
            throw new MigrationConsoleException("configuration_invalid", "A referenced JSON document is invalid.");
        }
        catch (IOException)
        {
            throw new MigrationConsoleException("configuration_unavailable", "A referenced JSON document is unavailable.");
        }
        catch (UnauthorizedAccessException)
        {
            throw new MigrationConsoleException("configuration_unavailable", "A referenced JSON document is unavailable.");
        }
    }

    private static async Task WriteNewJsonAsync<T>(string path, T value, CancellationToken cancellationToken)
    {
        string fullPath = Path.GetFullPath(path);
        _ = Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        await using FileStream stream = new(fullPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024,
            FileOptions.Asynchronous | FileOptions.WriteThrough);
        await JsonSerializer.SerializeAsync(stream, value, JsonOptions, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private sealed record MigrationConsoleConfiguration(ReceiptCommandConfiguration? Receipt);

    private sealed record ReceiptCommandConfiguration(string BackupStatePath, string OutputPath, string KeyId);

    private sealed record BackupStateDocument(IReadOnlyList<VerifiedBackupStateArtifact> Artifacts);
}

public sealed class MigrationConsoleException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

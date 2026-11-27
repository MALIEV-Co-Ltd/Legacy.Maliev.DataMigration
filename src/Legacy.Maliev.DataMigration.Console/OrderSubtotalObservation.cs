using System.Data;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record OrderSubtotalObservationExpectation(string Kind, string SourceIdentitySha256, DeltaTargetAuthority Target,
    string TargetNamespace, string TargetCluster, string TargetGeneration, CurrentAppOwnedMaintenancePin Maintenance);

internal sealed partial class OrderSubtotalRepairInputs
{
    internal static async Task<OrderSubtotalArtifact> ObserveAsync(string path, CancellationToken ct)
    {
        if (System.Reflection.Assembly.GetEntryAssembly() != typeof(MigrationConsole).Assembly) { throw Invalid(); }
        string accepted = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false);
        byte[] bytes = ReadLoose(path, 65536); var config = MigrationConsole.DecodeAuthRepair<OrderSubtotalRepairConfiguration>(bytes);
        if (config.Kind != "current-order-subtotal-observe-configuration-v1") { throw Invalid(); }
        var binding = MigrationConsole.DecodeAuthRepair<LocalExecutionBinding>(ReadLoose(config.RunBindingPath, 65536));
        using var authority = WindowsLocalRunAuthority.AcquireResume(Path.GetDirectoryName(path)!, binding); using var files = new CurrentAppOwnedRepairCustody(authority);
        if (!files.Read(path, sharedReader: true, maximumBytes: 65536).AsSpan().SequenceEqual(bytes)) { throw Invalid(); }
        var expected = MigrationConsole.DecodeAuthRepair<OrderSubtotalObservationExpectation>(Read(files, config.IntentClaim));
        if (expected.Kind != "current-order-subtotal-observation-expectation-v1" || !OrderSubtotalRepairProtocol.IsHash(expected.SourceIdentitySha256)) { throw Invalid(); }
        var trust = new ReceiptAttestationTrustStore(config.TrustedKeys.Select(key => new TrustedAttestationKey(key.KeyId,
            files.Read(key.SubjectPublicKeyInfoPath, sharedReader: true, maximumBytes: 65536))));
        CurrentAuthLocalSessionArchivePolicy.RequirePins(ArchivePins(config.SigningPins), trust);
        byte[] credential = Read(files, config.SourceCredential); ConsumerColumnBootstrapSourceCapture source;
        try { source = await ConsumerColumnBootstrapProofSourceCapture.CaptureAsync(new System.Text.UTF8Encoding(false, true).GetString(credential), expected.SourceIdentitySha256, accepted, ct).ConfigureAwait(false); }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(credential); }
        var pins = MigrationConsole.DecodeAuthRepair<CurrentAppOwnedRepairTargetPins>(Read(files, config.TargetPins));
        string[] names = expected.Target.Kind == DeltaTargetAuthorityKind.ProductionCloudNativePg ? [.. ReviewedProductionRepairInventory.ExportProductionNames()] :
            [.. DatabaseInventory.ActiveDatabases, "Auth", "postgres", "legacy_local"];
        DateTimeOffset issued = DateTimeOffset.UtcNow;
        string placeholder = new('0', 64);
        var draft = new OrderSubtotalRepairIntent(OrderSubtotalRepairProtocol.IntentKind, Guid.NewGuid(), accepted, source.FullPlanSha256,
            source.SourceIdentitySha256, SourceCatalogDefinitionFingerprintV1.Compute(source.Plan, accepted, source.SourceIdentitySha256, issued), placeholder, placeholder,
            OrderSubtotalRepairProtocol.CandidateSha256, expected.Target, expected.TargetNamespace, expected.TargetCluster, expected.TargetGeneration, OrderSubtotalRepairProtocol.Hash(pins),
            binding.ComputeSha256(), names.ToDictionary(x => x, _ => placeholder, StringComparer.Ordinal), names.ToDictionary(x => x, _ => placeholder, StringComparer.Ordinal), placeholder,
            "postgres", OrderSubtotalExpressionRepairContract.HistoricalExpression, expected.Maintenance, issued,
            issued.AddMinutes(5) < expected.Maintenance.ExpiresAtUtc ? issued.AddMinutes(5) : expected.Maintenance.ExpiresAtUtc);
        // This draft never enters RequireIntent or an execution path and is never signed/retained as observed.
        var input = new OrderSubtotalRepairInputs(authority, files, config, draft, null!, trust);
        string direct = input.Secret(config.OperatorConnection);
        using (var target = new OrderSubtotalPersistentTarget(pins, files, binding.ArtifactRootCanonicalPath))
        { await target.RequireAsync(draft, new NpgsqlConnectionStringBuilder(direct).Port, ct).ConfigureAwait(false); }
        string expression, owner;
        await using (var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(direct) { Database = "Order", Pooling = false }.ConnectionString))
        {
            await connection.OpenAsync(ct).ConfigureAwait(false); await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
            await DualTargetNativeProofLogicalCapture.ExecuteAsync(connection, tx, "SET TRANSACTION READ ONLY;", ct).ConfigureAwait(false);
            await OrderSubtotalRuntime.RequirePolicyAsync(connection, tx, expected.Maintenance, expected.Target, ct).ConfigureAwait(false);
            await using var read = new NpgsqlCommand("SELECT pg_get_expr(d.adbin,d.adrelid),pg_get_userbyid(c.relowner) FROM pg_attrdef d JOIN pg_attribute a ON a.attrelid=d.adrelid AND a.attnum=d.adnum JOIN pg_class c ON c.oid=a.attrelid WHERE a.attrelid='public.\"Order\"'::regclass AND a.attname='Subtotal' AND a.attgenerated='s';", connection, tx);
            await using (var reader = await read.ExecuteReaderAsync(ct).ConfigureAwait(false))
            { if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { throw Invalid(); } expression = reader.GetString(0); owner = reader.GetString(1); if (await reader.ReadAsync(ct).ConfigureAwait(false)) { throw Invalid(); } }
            await tx.RollbackAsync(ct).ConfigureAwait(false);
        }
        var contract = OrderSubtotalExpressionRepairContract.Create(source.Plan, accepted, expression, DateTimeOffset.UtcNow);
        draft = draft with { HistoricalExpression = expression, OrderOwnerName = owner, BeforePhysicalSha256 = contract.BeforePhysical().TargetSchemaSha256, AfterPhysicalSha256 = contract.AfterPhysical().TargetSchemaSha256 };
        input = new(authority, files, config, draft, null!, trust);
        using var runtime = OrderSubtotalRuntime.ForReadOnlyObservation(input, source, contract);
        var fleet = await runtime.FleetAsync(false, ct).ConfigureAwait(false);
        var nativeFleet = await runtime.NativeFleetAsync(ct).ConfigureAwait(false);
        var native = await runtime.NativeAsync(false, ct).ConfigureAwait(false);
        var intent = draft with
        {
            BeforeDatabaseSha256 = fleet.ToDictionary(x => x.Database, x => x.Sha256, StringComparer.Ordinal),
            BeforeNativeDatabaseSha256 = nativeFleet,
            NativePreimageSha256 = OrderSubtotalRepairProtocol.NativeSha(native),
            IssuedAtUtc = DateTimeOffset.UtcNow
        };
        _ = OrderSubtotalRepairProtocol.RequireIntent(intent, source.Plan, DateTimeOffset.UtcNow);
        using var signer = input.Signer(config.ReviewPrivateKey, config.SigningPins.ReviewKeyId, config.SigningPins.ReviewFingerprint);
        var claim = await input.PublishAsync("intent", CurrentAuthLocalSessionArchivePolicy.Sign(OrderSubtotalRepairProtocol.IntentDomain, intent, signer), intent.IntentId, ct).ConfigureAwait(false);
        var ready = config with { Kind = "current-order-subtotal-fixed-configuration-v1", IntentClaim = claim };
        return await input.PublishAsync("ready-configuration", ready, intent.IntentId, ct).ConfigureAwait(false);
    }
}

public static partial class MigrationConsole
{
    internal static async Task<int> RunOrderSubtotalOperationalAsync(string command, string path, TextWriter output, TextWriter error, CancellationToken ct)
    {
        try
        {
            if (command is not ("observe-current-order-subtotal" or "verify-current-order-subtotal" or "apply-current-order-subtotal" or "characterize-current-order-subtotal-faults") ||
                Environment.GetEnvironmentVariable("LEGACY_DEPLOY_ENABLED") != "false" || System.Reflection.Assembly.GetEntryAssembly() != typeof(MigrationConsole).Assembly) { throw OrderSubtotalRepairProtocol.Invalid(); }
            CurrentAuthArchiveCapacity.Require(admission: true); _ = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false);
            if (command == "observe-current-order-subtotal") { var result = await OrderSubtotalRepairInputs.ObserveAsync(path, ct).ConfigureAwait(false); await output.WriteLineAsync(result.Path).ConfigureAwait(false); return 0; }
            using var inputs = OrderSubtotalRepairInputs.Open(path); using var runtime = await OrderSubtotalRuntime.OpenAsync(inputs, ct).ConfigureAwait(false);
            if (command == "verify-current-order-subtotal") { await runtime.VerifyAsync(ct).ConfigureAwait(false); }
            else if (command == "apply-current-order-subtotal") { await runtime.ExecuteAsync(ct).ConfigureAwait(false); }
            else { await runtime.CharacterizeFaultsAsync(ct).ConfigureAwait(false); }
            await output.WriteLineAsync("order_subtotal_boundary_completed_no_parity_claim").ConfigureAwait(false); return 0;
        }
        catch (Exception failure) when (failure is MigrationExecutionException or MigrationConsoleException or IOException or UnauthorizedAccessException or
            System.Data.Common.DbException or JsonException or InvalidOperationException or ArgumentException or OperationCanceledException or AggregateException or System.Reflection.TargetInvocationException or System.Security.Cryptography.CryptographicException)
        { await error.WriteLineAsync("order_subtotal_boundary_failed_or_uncertain").ConfigureAwait(false); return 1; }
    }
}

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record HistoricalLocalContinuityIssueCommandConfiguration(
    HistoricalLocalReviewCommandConfiguration Historical,
    string FutureSchemaPath,
    string FuturePairPath,
    string DisposableProofPath,
    IReadOnlyList<DeltaTrustedKeyReference> TrustedKeys,
    string AuthorizationKeyId,
    string ContinuityKeyId,
    DateTimeOffset ExpiresAtUtc,
    string OutputPath);

public static partial class MigrationConsole
{
    private const string ContinuitySigningKeyEnvironmentVariable =
        "LEGACY_MIGRATION_LOCAL_CONTINUITY_SIGNING_KEY_FILE";

    internal static Task<int> RunHistoricalLocalContinuityIssueForTestsAsync(
        IReadOnlyList<string> arguments, TextWriter output, TextWriter error,
        Func<string, string?> environment, IHistoricalLocalReviewRuntime runtime,
        CancellationToken cancellationToken)
    {
        ConsoleInvocation invocation = ConsoleInvocation.Parse(arguments);
        return invocation.Command == "issue-historical-local-continuity"
            ? RunHistoricalLocalContinuityIssueBoundaryAsync(invocation.ConfigPath,
                environment, output, error, runtime, cancellationToken)
            : Task.FromResult(65);
    }

    private static async Task<int> RunHistoricalLocalContinuityIssueBoundaryAsync(
        string configPath, Func<string, string?> environment, TextWriter output,
        TextWriter error, IHistoricalLocalReviewRuntime runtime,
        CancellationToken cancellationToken)
    {
        try
        {
            if (!string.Equals(environment(DeployEnabledEnvironmentVariable), "false",
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new MigrationConsoleException("delta_deploy_gate_invalid", "Deployment must be disabled.");
            }
            GuardedDeltaCommandPolicy.ValidateCaller("issue-historical-local-continuity",
                environment("LEGACY_MIGRATION_CALLER"));
            MigrationConsoleConfiguration root = await ReadProtectedJsonAsync<MigrationConsoleConfiguration>(
                configPath, "delta_config_unprotected", cancellationToken).ConfigureAwait(false);
            HistoricalLocalContinuityIssueCommandConfiguration request = root.HistoricalLocalContinuityIssue ??
                throw new MigrationConsoleException("delta_historical_local_config_missing",
                    "A protected historical LOCAL continuity issue configuration is required.");
            HistoricalLocalReviewCommandConfiguration old = request.Historical;
            DeltaSynchronizationPlan historicalPlan = await ReadProtectedJsonAsync<DeltaSynchronizationPlan>(
                old.HistoricalPlanPath, "delta_historical_local_plan_unprotected", cancellationToken)
                .ConfigureAwait(false);
            Exact23DeltaReconciliationResult historicalReceipt =
                await ReadProtectedJsonAsync<Exact23DeltaReconciliationResult>(old.HistoricalReceiptPath,
                    "delta_historical_local_receipt_unprotected", cancellationToken).ConfigureAwait(false);
            FreshSchemaPlan historicalSchema = await ReadProtectedJsonAsync<FreshSchemaPlan>(
                old.HistoricalSchemaPath, "delta_historical_local_schema_unprotected", cancellationToken)
                .ConfigureAwait(false);
            FreshSchemaPlan futureSchema = await ReadProtectedJsonAsync<FreshSchemaPlan>(
                request.FutureSchemaPath, "delta_schema_plan_unprotected", cancellationToken).ConfigureAwait(false);
            PairedCapturedDeltaPlans futurePlans = await ReadProtectedJsonAsync<PairedCapturedDeltaPlans>(
                request.FuturePairPath, "delta_paired_plan_unprotected", cancellationToken).ConfigureAwait(false);
            Exact23DeltaReconciliationResult disposableProof =
                await ReadProtectedJsonAsync<Exact23DeltaReconciliationResult>(request.DisposableProofPath,
                    "delta_proof_result_unprotected", cancellationToken).ConfigureAwait(false);
            ReceiptAttestationTrustStore trust = await ReadTrustStoreAsync(
                [.. request.TrustedKeys.Select(key =>
                    new TrustedKeyReference(key.KeyId, key.SubjectPublicKeyInfoPath))],
                cancellationToken).ConfigureAwait(false);
            if (!trust.TryGetPublicKeyFingerprintSha256(request.AuthorizationKeyId,
                    out string authorizationFingerprint) ||
                !trust.TryGetPublicKeyFingerprintSha256(request.ContinuityKeyId,
                    out string continuityFingerprint))
            {
                throw new MigrationConsoleException("delta_historical_local_trust_invalid",
                    "The continuity signing roles must be independently trusted.");
            }
            using P256MigrationEvidenceSigner authorizationSigner = await ReadDeltaSignerAsync(environment,
                DeltaAuthorizationSigningKeyEnvironmentVariable, request.AuthorizationKeyId,
                authorizationFingerprint, "delta_authorization_signing_key_unprotected", cancellationToken)
                .ConfigureAwait(false);
            using P256MigrationEvidenceSigner continuitySigner = await ReadDeltaSignerAsync(environment,
                ContinuitySigningKeyEnvironmentVariable, request.ContinuityKeyId,
                continuityFingerprint, "delta_continuity_signing_key_unprotected", cancellationToken)
                .ConfigureAwait(false);
            string target = (await ReadProtectedTextAsync(old.TargetConnectionFile,
                "delta_historical_local_connection_unprotected", cancellationToken).ConfigureAwait(false)).Trim();
            _ = await runtime.ObserveAsync(old, target, historicalPlan, cancellationToken)
                .ConfigureAwait(false);
            await DefaultGuardedDeltaConsoleRuntime.VerifyTargetAuthorityAsync(target,
                futurePlans.Persistent.TargetAuthority ?? throw new MigrationConsoleException(
                    "delta_historical_local_authority_invalid", "A signed LOCAL target authority is required."),
                cancellationToken).ConfigureAwait(false);
            if (futureSchema.SchemaVersion != "2.0" || futureSchema.Databases is null ||
                !futureSchema.Databases.Select(database => database.Database)
                    .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal))
            {
                throw new MigrationConsoleException("delta_historical_local_schema_invalid",
                    "The future schema must retain the exact active database inventory.");
            }
            var futureInspector = new PostgreSqlDeltaReconciliationInspector(new(target));
            foreach (DatabaseSchemaPlan database in futureSchema.Databases)
            {
                if (database.Database == "Quotation")
                {
                    await futureInspector.ValidateQuotationTransitionSchemaAsync(database,
                        cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    await futureInspector.ValidateSchemaAsync(database, cancellationToken)
                        .ConfigureAwait(false);
                }
            }
            IDeltaReconciliationInspector inspector = runtime.CreateInspector(target, historicalPlan,
                historicalReceipt, historicalSchema, trust, TimeProvider.System.GetUtcNow());
            var metadata = new HistoricalPostgreSqlLocalMetadataInspector(target);
            HistoricalLocalContinuityIssuance issuance = await HistoricalLocalContinuityIssuer.IssueAsync(
                historicalPlan, historicalReceipt, historicalSchema, futurePlans, disposableProof,
                futureSchema, trust, token => runtime.ObserveAsync(old, target, historicalPlan, token),
                inspector, token => metadata.InspectAsync(historicalPlan, historicalReceipt,
                    historicalSchema, trust, TimeProvider.System.GetUtcNow(), token),
                request.ExpiresAtUtc, authorizationSigner, continuitySigner,
                TimeProvider.System, cancellationToken).ConfigureAwait(false);
            await WriteNewJsonAsync(request.OutputPath, issuance, cancellationToken).ConfigureAwait(false);
            await output.WriteLineAsync("issue_historical_local_continuity_complete").ConfigureAwait(false);
            return 0;
        }
        catch (Exception failure)
        {
            string code = failure is MigrationExecutionException { Reconciliation: { } }
                ? "shadow_reconciliation_failed" : ClassifyDeltaFailure(failure);
            if (code.Length > 100 || code.Any(value => value is not (>= 'a' and <= 'z') and not '_'))
            {
                code = "delta_execution_failed";
            }
            await error.WriteLineAsync(code).ConfigureAwait(false);
            if (failure is MigrationExecutionException { Reconciliation: { } diagnostic })
            {
                await WriteSafeHistoricalLocalDiagnosticAsync(error, diagnostic).ConfigureAwait(false);
            }
            return failure is OperationCanceledException ? 130 : 65;
        }
    }
}

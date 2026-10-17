using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CustomerClosedEightCase(string CaseId, Guid OperationId, string TestName, string TestId, string ExecutionId,
    string OriginalRoot, CustomerDefinitionArtifact Facts, CustomerDefinitionArtifact HostEntry, IReadOnlyList<CustomerDefinitionArtifact> Artifacts,
    DateTimeOffset TestBeganAtUtc, DateTimeOffset TestExitedAtUtc);
internal sealed record CustomerClosedEightReport(string Kind, string Purpose, CustomerDefinitionSubject IntendedSubject,
    CustomerClosedLaneInput CompletedComponents, CustomerDefinitionArtifact Trx, CustomerDefinitionArtifact HostExit,
    CustomerDefinitionArtifact HostCleanup, CustomerDefinitionArtifact HostAbsence, CustomerDefinitionArtifact HostBaseline, CustomerDefinitionArtifact TestAssembly,
    IReadOnlyList<CustomerClosedEightCase> Cases, DateTimeOffset BeganAtUtc, DateTimeOffset CompletedAtUtc, DateTimeOffset ExpiresAtUtc,
    string KeyId, string? Signature);
internal sealed record CustomerClosedEightAcceptance(CustomerDefinitionArtifact Native, CustomerDefinitionArtifact Maintenance,
    CustomerDefinitionArtifact Recovery, CustomerDefinitionArtifact RoleTransition);

internal static partial class CurrentCustomerClosedEightReadback
{
    internal static byte[] Payload(CustomerClosedEightReport report)
    {
        return [.. System.Text.Encoding.UTF8.GetBytes("Legacy.Maliev.CustomerSequence.ClosedEight.Console." + report.Purpose + ".v1\0"),
            .. JsonSerializer.SerializeToUtf8Bytes(report with { Signature = null })];
    }

    internal static void RequireHeader(CustomerClosedEightReport report, string purpose, IReceiptAttestationTrustStore trust,
        string key, string fingerprint, DateTimeOffset now)
    {
        if (report.Kind != "current-customer-sequence-closed-eight-console-proof-v1" || report.Purpose != purpose ||
            purpose is not ("native" or "maintenance" or "recovery" or "role-transition") || report.KeyId != key ||
            !trust.TryGetPublicKeyFingerprintSha256(key, out string actual) || actual != fingerprint || report.Signature is null ||
            now.Offset != TimeSpan.Zero || report.BeganAtUtc.Offset != TimeSpan.Zero || report.CompletedAtUtc.Offset != TimeSpan.Zero || report.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            report.CompletedAtUtc < report.BeganAtUtc || report.CompletedAtUtc > now || report.ExpiresAtUtc <= now || report.ExpiresAtUtc <= report.CompletedAtUtc ||
            report.ExpiresAtUtc - report.BeganAtUtc > TimeSpan.FromHours(12) || now - report.BeganAtUtc > TimeSpan.FromHours(12) ||
            report.Cases.Count != 8 || report.Cases.Select(x => x.OperationId).Distinct().Count() != 8 || report.Cases.Any(x => x.OperationId == Guid.Empty) ||
            !report.Cases.Select(x => x.CaseId).Order(StringComparer.Ordinal).SequenceEqual(CurrentCustomerSequenceClosedBootstrap.Cases.Order(StringComparer.Ordinal)) ||
            report.Cases.Select(x => x.TestId).Distinct(StringComparer.Ordinal).Count() != 8 || report.Cases.Select(x => x.ExecutionId).Distinct(StringComparer.Ordinal).Count() != 8 ||
            report.IntendedSubject.ConsoleAssemblySha256 != CustomerClosedCompletedReadback.Image(typeof(MigrationConsole).Assembly.Location) ||
            report.IntendedSubject.CoreAssemblySha256 != CustomerClosedCompletedReadback.Image(typeof(CurrentCustomerSequenceRepairPermit).Assembly.Location))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        try { if (!trust.Verify(key, Payload(report), Convert.FromBase64String(report.Signature))) { throw CurrentCustomerSequenceRepairPermit.Invalid(); } }
        catch (FormatException) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
    }
}

using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Legacy.Maliev.DataMigration;

public sealed record SourceScriptContract(string Path, string Sha256, string CanonicalTextSha256);

public sealed record SourceIdentityContract(long Seed, long Increment);

public sealed record SourceColumnContract(
    string Name,
    string StoreType,
    bool Nullable,
    SourceIdentityContract? Identity = null);

public sealed record SourceTableContract(
    string Name,
    IReadOnlyList<SourceColumnContract> Columns,
    IReadOnlyList<string> UniqueKeys)
{
    public SourceColumnContract Column(string name)
    {
        return Columns.Single(column => string.Equals(column.Name, name, StringComparison.Ordinal));
    }
}

public sealed record QuotationOutcomeSourceRow(
    long ID,
    string EventKey,
    int QuotationID,
    int? SourceRequestID,
    Guid? SourceJourneyID,
    DateTime AcceptedUtc,
    string AcceptanceOrigin);

public sealed record QuotationAcceptedOutcomeImportRow(
    long ID,
    string EventKey,
    int QuotationID,
    int? SourceRequestID,
    Guid? SourceJourneyID,
    DateTime AcceptedUtc,
    string AcceptanceOrigin);

public sealed record QuotationOutcomeImportPlan(
    IReadOnlyList<QuotationAcceptedOutcomeImportRow> Inserts,
    IReadOnlyList<QuotationAcceptedOutcomeImportRow> AlreadyApplied,
    long NextIdentity);

public sealed class QuotationOutcomeTransformException(string code, string message) : InvalidOperationException(message)
{
    public string Code { get; } = code;
}

public static class QuotationOutcomeTransformPlanner
{
    public static string ComputeContentSha256(IEnumerable<QuotationOutcomeSourceRow> sourceRows)
    {
        ArgumentNullException.ThrowIfNull(sourceRows);
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream, new UTF8Encoding(false), leaveOpen: true);
        foreach (QuotationOutcomeSourceRow row in sourceRows.OrderBy(row => row.ID))
        {
            writer.Write(row.ID);
            WriteString(writer, row.EventKey);
            writer.Write(row.QuotationID);
            writer.Write(row.SourceRequestID.HasValue);
            if (row.SourceRequestID.HasValue)
            {
                writer.Write(row.SourceRequestID.Value);
            }

            writer.Write(row.SourceJourneyID.HasValue);
            if (row.SourceJourneyID.HasValue)
            {
                writer.Write(row.SourceJourneyID.Value.ToByteArray());
            }

            writer.Write(row.AcceptedUtc.Ticks);
            WriteString(writer, row.AcceptanceOrigin);
        }

        return Convert.ToHexString(SHA256.HashData(stream.ToArray())).ToLowerInvariant();
    }

    public static QuotationAcceptedOutcomeImportRow Map(QuotationOutcomeSourceRow source)
    {
        ArgumentNullException.ThrowIfNull(source);
        ValidateSource(source);
        return new(
            source.ID,
            source.EventKey,
            source.QuotationID,
            source.SourceRequestID,
            source.SourceJourneyID,
            source.AcceptedUtc,
            source.AcceptanceOrigin);
    }

    public static QuotationOutcomeImportPlan Create(
        IReadOnlyCollection<QuotationOutcomeSourceRow> sourceRows,
        IReadOnlyCollection<QuotationAcceptedOutcomeImportRow> existingRows,
        long sourceNextIdentity)
    {
        ArgumentNullException.ThrowIfNull(sourceRows);
        ArgumentNullException.ThrowIfNull(existingRows);

        QuotationAcceptedOutcomeImportRow[] mapped = sourceRows.Select(Map).ToArray();
        if (mapped.Select(row => row.ID).Distinct().Count() != mapped.Length ||
            mapped.Select(row => row.EventKey).Distinct(StringComparer.Ordinal).Count() != mapped.Length)
        {
            throw new QuotationOutcomeTransformException(
                "quotation_outcome_source_duplicate",
                "The source outcome inventory contains duplicate identities or event keys.");
        }

        long minimumNextIdentity = mapped.Length == 0 ? 1 : checked(mapped.Max(row => row.ID) + 1);
        if (sourceNextIdentity < minimumNextIdentity)
        {
            throw new QuotationOutcomeTransformException(
                "quotation_outcome_identity_drift",
                "The observed source next identity is behind the source row inventory.");
        }

        if (existingRows.Select(row => row.ID).Distinct().Count() != existingRows.Count ||
            existingRows.Select(row => row.EventKey).Distinct(StringComparer.Ordinal).Count() != existingRows.Count)
        {
            throw new QuotationOutcomeTransformException(
                "quotation_outcome_replay_conflict",
                "The canonical outcome inventory contains duplicate identities or event keys.");
        }

        Dictionary<string, QuotationAcceptedOutcomeImportRow> existingByEventKey =
            existingRows.ToDictionary(row => row.EventKey, StringComparer.Ordinal);
        Dictionary<long, QuotationAcceptedOutcomeImportRow> existingById =
            existingRows.ToDictionary(row => row.ID);
        HashSet<string> sourceEventKeys = mapped.Select(row => row.EventKey).ToHashSet(StringComparer.Ordinal);
        HashSet<long> sourceIds = mapped.Select(row => row.ID).ToHashSet();
        if (existingRows.Any(row => !sourceEventKeys.Contains(row.EventKey) || !sourceIds.Contains(row.ID)))
        {
            throw new QuotationOutcomeTransformException(
                "quotation_outcome_replay_conflict",
                "The canonical inventory contains outcomes absent from the complete source inventory.");
        }
        var inserts = new List<QuotationAcceptedOutcomeImportRow>();
        var alreadyApplied = new List<QuotationAcceptedOutcomeImportRow>();

        foreach (QuotationAcceptedOutcomeImportRow row in mapped.OrderBy(row => row.ID))
        {
            if (!existingByEventKey.TryGetValue(row.EventKey, out QuotationAcceptedOutcomeImportRow? existing))
            {
                if (existingById.ContainsKey(row.ID))
                {
                    throw new QuotationOutcomeTransformException(
                        "quotation_outcome_replay_conflict",
                        $"Source identity '{row.ID}' is already assigned to another canonical event.");
                }

                inserts.Add(row);
                continue;
            }

            if (existing != row)
            {
                throw new QuotationOutcomeTransformException(
                    "quotation_outcome_replay_conflict",
                    $"Existing canonical outcome '{row.EventKey}' does not exactly match its source row.");
            }

            alreadyApplied.Add(existing);
        }

        return new(inserts, alreadyApplied, sourceNextIdentity);
    }

    private static void ValidateSource(QuotationOutcomeSourceRow source)
    {
        if (source.ID <= 0 || source.QuotationID <= 0 || string.IsNullOrWhiteSpace(source.EventKey) ||
            source.EventKey.Length > 128 || string.IsNullOrWhiteSpace(source.AcceptanceOrigin) ||
            source.AcceptanceOrigin.Length > 16 || source.AcceptedUtc.Kind != DateTimeKind.Unspecified)
        {
            throw new QuotationOutcomeTransformException(
                "quotation_outcome_source_invalid",
                "The source outcome row violates the signed source contract.");
        }
    }

    private static void WriteString(BinaryWriter writer, string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value);
        writer.Write(bytes.Length);
        writer.Write(bytes);
    }
}

public sealed record QuotationOutcomeFieldMapping(string Source, string Target);

public sealed record AnalyticsArchiveContract(
    string Table,
    bool ReadOnly,
    bool RuntimeWorkerEnabled,
    bool DirectGoogleAnalyticsCredentialsAllowed);

public sealed record QuotationOutcomeAdoptionMode(string Mode, bool ImporterMayExecuteDdl);

public sealed record QuotationOutcomeInventoryContract(long RowCount, string ContentSha256, long NextIdentity);

public sealed record QuotationOutcomeDataContract(
    QuotationOutcomeInventoryContract Source,
    QuotationOutcomeInventoryContract ExpectedCanonical,
    IReadOnlyList<long> InsertIds,
    IReadOnlyList<long> ReplayIds);

public sealed record QuotationOutcomeAdoptionContract(
    string SourceCommitSha,
    string SourceContractSha256,
    string CanonicalTargetSchemaSha256,
    string AttestationKeyId,
    string OutcomeSourceTable,
    string CanonicalTargetTable,
    IReadOnlyList<QuotationOutcomeFieldMapping> FieldMappings,
    bool PreserveSourceIdentity,
    bool PreserveNextIdentity,
    bool SynthesizeMissingAcceptedQuotations,
    AnalyticsArchiveContract AnalyticsArchive,
    QuotationOutcomeAdoptionMode Adoption,
    string? AttestationSignature = null)
{
    public QuotationOutcomeDataContract? Data { get; init; }
}

public sealed record QuotationAdoptionObservation(
    string SourceCommitSha,
    string SourceContractSha256,
    string CanonicalTargetSchemaSha256,
    bool CanonicalSchemaCreatedByEf,
    bool ImporterExecutedDdl,
    IReadOnlyList<string> AnalyticsArchivePrivileges,
    bool RuntimeWorkerConfigured,
    bool DirectGoogleAnalyticsCredentialsConfigured)
{
    public QuotationOutcomeInventoryContract? VerifiedCanonical { get; init; }
}

public sealed class QuotationOutcomeAdoptionException(string code, string message) : InvalidOperationException(message)
{
    public string Code { get; } = code;
}

public static class QuotationOutcomeAdoptionValidator
{
    public static void Validate(QuotationOutcomeAdoptionContract contract, QuotationAdoptionObservation observation)
    {
        ArgumentNullException.ThrowIfNull(contract);
        ArgumentNullException.ThrowIfNull(observation);

        bool archiveIsSelectOnly = observation.AnalyticsArchivePrivileges.Count == 1 &&
            string.Equals(observation.AnalyticsArchivePrivileges[0], "SELECT", StringComparison.Ordinal);
        if (!string.Equals(observation.SourceCommitSha, contract.SourceCommitSha, StringComparison.Ordinal) ||
            !FixedTimeShaEquals(observation.SourceContractSha256, contract.SourceContractSha256) ||
            !FixedTimeShaEquals(observation.CanonicalTargetSchemaSha256, contract.CanonicalTargetSchemaSha256) ||
            !observation.CanonicalSchemaCreatedByEf || observation.ImporterExecutedDdl || !archiveIsSelectOnly ||
            observation.RuntimeWorkerConfigured || observation.DirectGoogleAnalyticsCredentialsConfigured ||
            contract.Data is null || observation.VerifiedCanonical is null ||
            observation.VerifiedCanonical != contract.Data.ExpectedCanonical)
        {
            throw new QuotationOutcomeAdoptionException(
                "quotation_adoption_drift",
                "Observed adoption state does not match the reviewed fail-closed contract.");
        }
    }

    private static bool FixedTimeShaEquals(string left, string right)
    {
        return left.Length == 64 && right.Length == 64 &&
            left.All(char.IsAsciiHexDigit) && right.All(char.IsAsciiHexDigit) &&
            CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(left.ToLowerInvariant()),
                Encoding.ASCII.GetBytes(right.ToLowerInvariant()));
    }
}

public static class QuotationOutcomeAdoptionAttestation
{
    private const string DomainSeparator = "Legacy.Maliev.DataMigration.QuotationOutcomeAdoption.v1";

    public static QuotationOutcomeAdoptionContract Sign(QuotationOutcomeAdoptionContract contract, ECDsa signer)
    {
        ArgumentNullException.ThrowIfNull(contract);
        ArgumentNullException.ThrowIfNull(signer);
        byte[] signature = signer.SignData(CreatePayload(contract), HashAlgorithmName.SHA256);
        return contract with { AttestationSignature = Convert.ToBase64String(signature) };
    }

    public static bool Verify(QuotationOutcomeAdoptionContract contract, IReceiptAttestationTrustStore trustStore)
    {
        ArgumentNullException.ThrowIfNull(contract);
        ArgumentNullException.ThrowIfNull(trustStore);
        if (string.IsNullOrWhiteSpace(contract.AttestationSignature))
        {
            return false;
        }

        try
        {
            return trustStore.Verify(
                contract.AttestationKeyId,
                CreatePayload(contract),
                Convert.FromBase64String(contract.AttestationSignature));
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static byte[] CreatePayload(QuotationOutcomeAdoptionContract contract)
    {
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream, new UTF8Encoding(false), leaveOpen: true);
        Write(writer, DomainSeparator);
        Write(writer, contract.SourceCommitSha);
        Write(writer, contract.SourceContractSha256);
        Write(writer, contract.CanonicalTargetSchemaSha256);
        Write(writer, contract.AttestationKeyId);
        Write(writer, contract.OutcomeSourceTable);
        Write(writer, contract.CanonicalTargetTable);
        writer.Write(contract.FieldMappings.Count);
        foreach (QuotationOutcomeFieldMapping mapping in contract.FieldMappings)
        {
            Write(writer, mapping.Source);
            Write(writer, mapping.Target);
        }

        writer.Write(contract.PreserveSourceIdentity);
        writer.Write(contract.PreserveNextIdentity);
        writer.Write(contract.SynthesizeMissingAcceptedQuotations);
        Write(writer, contract.AnalyticsArchive.Table);
        writer.Write(contract.AnalyticsArchive.ReadOnly);
        writer.Write(contract.AnalyticsArchive.RuntimeWorkerEnabled);
        writer.Write(contract.AnalyticsArchive.DirectGoogleAnalyticsCredentialsAllowed);
        Write(writer, contract.Adoption.Mode);
        writer.Write(contract.Adoption.ImporterMayExecuteDdl);
        writer.Write(contract.Data is not null);
        if (contract.Data is not null)
        {
            WriteInventory(writer, contract.Data.Source);
            WriteInventory(writer, contract.Data.ExpectedCanonical);
            WriteLongs(writer, contract.Data.InsertIds);
            WriteLongs(writer, contract.Data.ReplayIds);
        }
        return stream.ToArray();
    }

    private static void Write(BinaryWriter writer, string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value);
        writer.Write(bytes.Length);
        writer.Write(bytes);
    }

    private static void WriteInventory(BinaryWriter writer, QuotationOutcomeInventoryContract inventory)
    {
        writer.Write(inventory.RowCount);
        Write(writer, inventory.ContentSha256);
        writer.Write(inventory.NextIdentity);
    }

    private static void WriteLongs(BinaryWriter writer, IReadOnlyList<long> values)
    {
        writer.Write(values.Count);
        foreach (long value in values)
        {
            writer.Write(value);
        }
    }
}

public static class CurrentQuotationSourceContract
{
    public const string SourceCommitSha = "7b4b2af697207d36a6e7b7784dddefa150193e97";

    public static readonly IReadOnlyList<SourceScriptContract> SourceScripts =
    [
        new("Maliev.SqlServer/Deployments/2026-08-12-ga4-quotation-lifecycle.sql", "5f4e276c1a281625153aefbfef129fb20232ff053e3a3142483e79acc6db98c6", "c1b0e4bada8e404297e4baf147526d74a69dba7db83d517a057039fecc8c2c70"),
        new("Maliev.SqlServer/Deployments/2026-08-23-quotation-qualified-outcome.sql", "f112303fb61c53e80b470ac6f2a3e892bff6061da13efda46cf52a63423fb912", "8e273c6fe4e4ed4d0fb36bf937233524bfcb56cdba25e1438d203bedd6253369"),
        new("Maliev.SqlServer/Deployments/2026-08-30-ga4-quotation-source-reconciliation.sql", "e713841ba8f056e37a7e233a58323859bf4ba9fc57eadd3a149a0a71759928fc", "f0a686ec98d57200e28ee8b66fb81d685e4bbed92904722b694fe56bc9956ca1"),
    ];

    public static readonly SourceTableContract GoogleAnalyticsOutbox = new(
        "dbo.GoogleAnalyticsOutbox",
        [
            new("ID", "bigint", false, new(1, 1)),
            new("QuotationID", "int", false),
            new("EventKey", "nvarchar(128)", false),
            new("EventName", "nvarchar(40)", false),
            new("ClientId", "nvarchar(128)", false),
            new("SessionId", "nvarchar(128)", false),
            new("UserId", "nvarchar(128)", true),
            new("Currency", "varchar(3)", false),
            new("Value", "decimal(18,2)", false),
            new("OccurredUtc", "datetime2(7)", false),
            new("AttemptCount", "int", false),
            new("NextAttemptUtc", "datetime2(7)", false),
            new("LeaseToken", "uniqueidentifier", true),
            new("LeaseUntilUtc", "datetime2(7)", true),
            new("SentUtc", "datetime2(7)", true),
            new("FailedUtc", "datetime2(7)", true),
            new("LastError", "nvarchar(1024)", true),
            new("SourceRequestID", "int", true),
            new("SourceJourneyID", "uniqueidentifier", true),
        ],
        ["UX_GoogleAnalyticsOutbox_EventKey"]);

    public static readonly SourceTableContract QuotationOutcomeOutbox = new(
        "dbo.QuotationOutcomeOutbox",
        [
            new("ID", "bigint", false, new(1, 1)),
            new("EventKey", "nvarchar(128)", false),
            new("QuotationID", "int", false),
            new("SourceRequestID", "int", true),
            new("SourceJourneyID", "uniqueidentifier", true),
            new("AcceptedUtc", "datetime2(7)", false),
            new("AcceptanceOrigin", "varchar(16)", false),
        ],
        ["UQ_QuotationOutcomeOutbox_EventKey"]);

    public static string SourceContractSha256 { get; } = ComputeSourceContractSha256();

    public static QuotationOutcomeAdoptionContract CreateAdoptionContract(
        string canonicalTargetSchemaSha256,
        string attestationKeyId,
        IReadOnlyCollection<QuotationOutcomeSourceRow> sourceRows,
        IReadOnlyCollection<QuotationAcceptedOutcomeImportRow> existingRows,
        long sourceNextIdentity)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(canonicalTargetSchemaSha256);
        ArgumentException.ThrowIfNullOrWhiteSpace(attestationKeyId);
        if (canonicalTargetSchemaSha256.Length != 64 || !canonicalTargetSchemaSha256.All(char.IsAsciiHexDigit))
        {
            throw new ArgumentException("Target schema digest must be a SHA-256 value.", nameof(canonicalTargetSchemaSha256));
        }

        string[] fields = ["ID", "EventKey", "QuotationID", "SourceRequestID", "SourceJourneyID", "AcceptedUtc", "AcceptanceOrigin"];
        QuotationOutcomeImportPlan plan = QuotationOutcomeTransformPlanner.Create(sourceRows, existingRows, sourceNextIdentity);
        var inventory = new QuotationOutcomeInventoryContract(
            sourceRows.Count,
            QuotationOutcomeTransformPlanner.ComputeContentSha256(sourceRows),
            sourceNextIdentity);
        return new(
            SourceCommitSha,
            SourceContractSha256,
            canonicalTargetSchemaSha256.ToLowerInvariant(),
            attestationKeyId,
            QuotationOutcomeOutbox.Name,
            "QuotationAcceptedOutcome",
            fields.Select(field => new QuotationOutcomeFieldMapping(field, field)).ToArray(),
            PreserveSourceIdentity: true,
            PreserveNextIdentity: true,
            SynthesizeMissingAcceptedQuotations: false,
            new("legacy_compatibility.GoogleAnalyticsOutbox", true, false, false),
            new("ef-schema-first-dml-only", false))
        {
            Data = new(
                inventory,
                inventory,
                plan.Inserts.Select(row => row.ID).ToArray(),
                plan.AlreadyApplied.Select(row => row.ID).ToArray()),
        };
    }

    private static string ComputeSourceContractSha256()
    {
        var builder = new StringBuilder();
        _ = builder.Append(SourceCommitSha).Append('\n');
        foreach (SourceScriptContract script in SourceScripts)
        {
            _ = builder.Append(script.Path).Append('|').Append(script.Sha256).Append('|').Append(script.CanonicalTextSha256).Append('\n');
        }

        AppendTable(builder, GoogleAnalyticsOutbox);
        AppendTable(builder, QuotationOutcomeOutbox);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(builder.ToString()))).ToLowerInvariant();
    }

    private static void AppendTable(StringBuilder builder, SourceTableContract table)
    {
        _ = builder.Append(table.Name).Append('\n');
        foreach (SourceColumnContract column in table.Columns)
        {
            _ = builder.Append(column.Name).Append('|').Append(column.StoreType).Append('|')
                .Append(column.Nullable ? '1' : '0').Append('|')
                .Append(column.Identity?.Seed.ToString(CultureInfo.InvariantCulture) ?? "-").Append('|')
                .Append(column.Identity?.Increment.ToString(CultureInfo.InvariantCulture) ?? "-").Append('\n');
        }

        foreach (string key in table.UniqueKeys)
        {
            _ = builder.Append("unique|").Append(key).Append('\n');
        }
    }
}

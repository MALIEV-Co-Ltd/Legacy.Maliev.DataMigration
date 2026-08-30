using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Legacy.Maliev.DataMigration;

public sealed record QuotationSchemaBaselineReceiptRequest(
    string Workload,
    string SourceSnapshotId,
    string CopyPlanId,
    DatabaseSchemaPlan SchemaPlan,
    string Host,
    int Port,
    string Database,
    DateTimeOffset ExpiresUtc);

public sealed record QuotationSchemaBaselineReceiptPayload(
    string SchemaVersion,
    string Workload,
    string SourceSnapshotId,
    string CopyPlanId,
    string SchemaHash,
    string AttestationKeyId,
    string Host,
    int Port,
    string Database,
    DateTimeOffset ExpiresUtc);

public sealed record QuotationSchemaBaselineReceipt(string EnvelopeJson);

public static partial class QuotationSchemaBaselineReceiptProducer
{
    public static QuotationSchemaBaselineReceipt Produce(
        QuotationSchemaBaselineReceiptRequest request,
        P256MigrationEvidenceSigner signer)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(signer);
        string requiredDatabase = request.Workload switch
        {
            "quotation" => "Quotation",
            "quotation-request" => "QuotationRequest",
            _ => throw Invalid(),
        };
        if (!string.Equals(request.Database, requiredDatabase, StringComparison.Ordinal) ||
            !string.Equals(request.SchemaPlan.Database, requiredDatabase, StringComparison.Ordinal) ||
            !Identifier().IsMatch(request.SourceSnapshotId) ||
            !Identifier().IsMatch(request.CopyPlanId) ||
            !Identifier().IsMatch(signer.KeyId) ||
            !Sha256().IsMatch(request.SchemaPlan.TargetSchemaSha256) ||
            string.IsNullOrWhiteSpace(request.Host) || request.Port is < 1 or > 65535 ||
            request.ExpiresUtc.Offset != TimeSpan.Zero || request.ExpiresUtc <= DateTimeOffset.UtcNow ||
            request.ExpiresUtc > DateTimeOffset.UtcNow.AddHours(24))
        {
            throw Invalid();
        }

        var payload = new QuotationSchemaBaselineReceiptPayload(
            "1.0", request.Workload, request.SourceSnapshotId, request.CopyPlanId,
            request.SchemaPlan.TargetSchemaSha256.ToLowerInvariant(), signer.KeyId,
            request.Host, request.Port, request.Database, request.ExpiresUtc);
        string payloadJson = JsonSerializer.Serialize(payload);
        string signature = Convert.ToBase64String(signer.Sign(QuotationSchemaBaselineReceiptCanonicalizer.CreatePayload(payload)));
        return new(JsonSerializer.Serialize(new { Payload = payloadJson, Signature = signature }));
    }

    private static MigrationExecutionException Invalid()
    {
        return new("quotation_schema_receipt_invalid", "Quotation schema-baseline receipt inputs are invalid or ambiguous.");
    }

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$", RegexOptions.CultureInvariant)]
    private static partial Regex Identifier();

    [GeneratedRegex("^[0-9a-fA-F]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex Sha256();
}

public static class QuotationSchemaBaselineReceiptCanonicalizer
{
    private const string DomainSeparator = "Legacy.Maliev.QuotationService.SchemaBaselineReceipt.v1";

    public static byte[] CreatePayload(QuotationSchemaBaselineReceiptPayload payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream, new UTF8Encoding(false), leaveOpen: true))
        {
            Write(writer, DomainSeparator);
            Write(writer, payload.SchemaVersion);
            Write(writer, payload.Workload);
            Write(writer, payload.SourceSnapshotId);
            Write(writer, payload.CopyPlanId);
            Write(writer, payload.SchemaHash);
            Write(writer, payload.AttestationKeyId);
            Write(writer, payload.Host);
            writer.Write(payload.Port);
            Write(writer, payload.Database);
            Write(writer, payload.ExpiresUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
        }
        return stream.ToArray();
    }

    private static void Write(BinaryWriter writer, string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value);
        writer.Write(bytes.Length);
        writer.Write(bytes);
    }
}

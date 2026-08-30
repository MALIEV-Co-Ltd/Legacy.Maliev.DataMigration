using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class QuotationSchemaBaselineReceiptProducerTests
{
    [Theory]
    [InlineData("quotation", "Quotation")]
    [InlineData("quotation-request", "QuotationRequest")]
    public void Produce_SignsExactQuotationConsumerContract(string workload, string database)
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signer = new P256MigrationEvidenceSigner("quotation-schema-v1", key.ExportECPrivateKeyPem());
        var request = Request(workload, database);

        QuotationSchemaBaselineReceipt receipt = QuotationSchemaBaselineReceiptProducer.Produce(request, signer);

        using JsonDocument envelope = JsonDocument.Parse(receipt.EnvelopeJson);
        string payloadJson = envelope.RootElement.GetProperty("Payload").GetString()!;
        byte[] signature = Convert.FromBase64String(envelope.RootElement.GetProperty("Signature").GetString()!);
        QuotationSchemaBaselineReceiptPayload payload = JsonSerializer.Deserialize<QuotationSchemaBaselineReceiptPayload>(payloadJson)!;
        Assert.Equal("1.0", payload.SchemaVersion);
        Assert.Equal(workload, payload.Workload);
        Assert.Equal(request.SchemaPlan.TargetSchemaSha256, payload.SchemaHash);
        Assert.True(key.VerifyData(QuotationSchemaBaselineReceiptCanonicalizer.CreatePayload(payload), signature, HashAlgorithmName.SHA256));
    }

    [Fact]
    public void Produce_RejectsDatabaseWorkloadMismatch()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signer = new P256MigrationEvidenceSigner("quotation-schema-v1", key.ExportECPrivateKeyPem());

        _ = Assert.Throws<MigrationExecutionException>(() =>
            QuotationSchemaBaselineReceiptProducer.Produce(Request("quotation", "QuotationRequest"), signer));
    }

    [Fact]
    public void Produce_RejectsExpiredOrInvalidIdentifiers()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signer = new P256MigrationEvidenceSigner("quotation-schema-v1", key.ExportECPrivateKeyPem());
        var request = Request("quotation", "Quotation") with { ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(-1) };

        _ = Assert.Throws<MigrationExecutionException>(() => QuotationSchemaBaselineReceiptProducer.Produce(request, signer));
        _ = Assert.Throws<MigrationExecutionException>(() => QuotationSchemaBaselineReceiptProducer.Produce(
            Request("quotation", "Quotation") with { SchemaPlan = Request("quotation", "Quotation").SchemaPlan with { TargetSchemaSha256 = "not-a-hash" } }, signer));
    }

    private static QuotationSchemaBaselineReceiptRequest Request(string workload, string database)
    {
        return new(
            workload,
            "source-20260830",
            "copy-plan-20260830",
            new DatabaseSchemaPlan(database, "202608300001", new string('a', 64), new string('b', 64), []),
            "legacy-postgres-pooler-rw.maliev-legacy.svc.cluster.local",
            5432,
            database,
            DateTimeOffset.UtcNow.AddHours(1));
    }
}

using System.Text;
using System.Text.Json.Nodes;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class RecoveryOriginalWireTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OriginalWire_AdmissionAndExpiredApprovalResume_PreserveExactOriginals(bool webOriginals)
    {
        using var data = await RecoveryAuthorityTestData.CreateAsync(webOriginals: webOriginals);
        InitialMigrationAdmission parsed = InitialMigrationAdmission.Parse(data.Admission.ExactJson);
        data.Verifier.ValidateAdmission(parsed, data.Now);
        data.ValidateResume();
        Assert.Equal(data.Admission.ComputeSha256(), parsed.ComputeSha256());
        Assert.Equal(data.AdmissionPayload.OriginalAuthorizationSha256, parsed.Payload.OriginalAuthorizationSha256);
        Assert.Equal(data.AdmissionPayload.VerifiedRestoreSha256, parsed.Payload.VerifiedRestoreSha256);
        string[] originals = Originals(data.AdmissionPayload);
        string[] retained = Originals(parsed.Payload);
        for (int i = 0; i < originals.Length; i++)
        {
            Assert.Contains(webOriginals ? "\"schemaVersion\"" : "\"SchemaVersion\"", originals[i]);
            Assert.Equal(Encoding.UTF8.GetBytes(originals[i]), Encoding.UTF8.GetBytes(retained[i]));
        }
        Assert.All(data.Resume.Payload.PermittedOperations, item => Assert.Equal(RecoveryDatabaseOperation.CreateCopyAndDeliver, item.Operation));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task ProducerOriginals_MalformedMissingNullUnknownAndDuplicateProperties_FailClosed(int index)
    {
        using var data = await RecoveryAuthorityTestData.CreateAsync(prepare: false, webOriginals: true);
        string[] originals = Originals(data.AdmissionPayload);
        Validate(originals);
        JsonObject document = JsonNode.Parse(originals[index])!.AsObject();
        JsonObject missing = document.DeepClone().AsObject();
        Assert.True(missing.Remove("schemaVersion"));
        JsonObject nullValue = document.DeepClone().AsObject();
        nullValue["schemaVersion"] = null;
        JsonObject nullItem = document.DeepClone().AsObject();
        string arrayName = index switch { 0 or 3 => "artifacts", 1 => "databases", _ => "authorizedDatabases" };
        nullItem[arrayName]!.AsArray()[0] = null;
        string original = document.ToJsonString();
        foreach (string malformed in new[]
        {
            "{", "null", missing.ToJsonString(), nullValue.ToJsonString(), nullItem.ToJsonString(),
            "{\"unapproved\":true," + original[1..],
            "{\"schemaVersion\":\"contradictory\"," + original[1..],
            "{\"SchemaVersion\":\"contradictory\"," + original[1..],
            "{\"SCHEMAVERSION\":\"contradictory\"," + original[1..],
        })
        {
            string[] changed = [.. originals];
            changed[index] = malformed;
            Assert.Equal("recovery_authority_invalid", Assert.Throws<MigrationExecutionException>(() => Validate(changed)).Code);
        }
        void Validate(string[] values)
        {
            data.Verifier.ValidateOriginalInputs(values[0], values[1], values[2], values[3], data.AdmittedAt);
        }
    }

    [Fact]
    public async Task OriginalWire_CamelCaseDoesNotRelaxNewEnvelopeOrPayloadCasing()
    {
        using var data = await RecoveryAuthorityTestData.CreateAsync(webOriginals: true);
        string envelope = data.Admission.ExactJson.Replace("\"PayloadJson\":", "\"payloadJson\":", StringComparison.Ordinal);
        _ = Assert.Throws<MigrationExecutionException>(() => InitialMigrationAdmission.Parse(envelope));
        JsonObject parsed = JsonNode.Parse(data.Admission.ExactJson)!.AsObject();
        string payload = parsed["PayloadJson"]!.GetValue<string>();
        parsed["PayloadJson"] = payload.Replace("\"OriginalBackupReceiptJson\":", "\"originalBackupReceiptJson\":", StringComparison.Ordinal);
        _ = Assert.Throws<MigrationExecutionException>(() => InitialMigrationAdmission.Parse(parsed.ToJsonString()));
    }

    [Fact]
    public async Task OriginalReader_RequiredNullableConstructorFieldAndNonNullableNestedFieldsRemainStrict()
    {
        using var data = await RecoveryAuthorityTestData.CreateAsync(prepare: false, webOriginals: true);
        JsonObject restore = JsonNode.Parse(data.AdmissionPayload.OriginalVerifiedRestoreReceiptJson)!.AsObject();
        Assert.Null(restore["cleanedAtUtc"]);
        _ = OriginalMigrationDocumentReader.Read<VerifiedRestoreReceipt>(restore.ToJsonString());
        Assert.True(restore.Remove("cleanedAtUtc"));
        _ = Assert.Throws<MigrationExecutionException>(() => OriginalMigrationDocumentReader.Read<VerifiedRestoreReceipt>(restore.ToJsonString()));
        restore["cleanedAtUtc"] = null;
        restore["resources"]!["volumeName"] = null;
        _ = Assert.Throws<MigrationExecutionException>(() => OriginalMigrationDocumentReader.Read<VerifiedRestoreReceipt>(restore.ToJsonString()));
    }

    [Fact]
    public async Task OriginalReader_NestedAliasesRejectedWhileCaseDistinctDictionaryKeysArePreserved()
    {
        using var data = await RecoveryAuthorityTestData.CreateAsync(prepare: false, webOriginals: true);
        JsonObject plan = JsonNode.Parse(data.AdmissionPayload.OriginalSchemaPlanJson)!.AsObject();
        JsonNode table = plan["databases"]![0]!["tables"]![0]!;
        table["columnTypes"]!["id"] = "text";
        FreshSchemaPlan decoded = OriginalMigrationDocumentReader.Read<FreshSchemaPlan>(plan.ToJsonString());
        Assert.Equal("integer", decoded.Databases[0].Tables[0].ColumnTypes!["ID"]);
        Assert.Equal("text", decoded.Databases[0].Tables[0].ColumnTypes!["id"]);
        table["targetSchema"] = "public";
        table["TargetSchema"] = "contradictory";
        _ = Assert.Throws<MigrationExecutionException>(() => OriginalMigrationDocumentReader.Read<FreshSchemaPlan>(plan.ToJsonString()));
        _ = table.AsObject().Remove("TargetSchema");
        table["unknown"] = true;
        _ = Assert.Throws<MigrationExecutionException>(() => OriginalMigrationDocumentReader.Read<FreshSchemaPlan>(plan.ToJsonString()));
    }

    [Fact]
    public void OriginalReader_SizeAndDepthLimitsRemainFailClosed()
    {
        string tooLarge = new(' ', (64 * 1024 * 1024) + 1);
        MigrationExecutionException size = Assert.Throws<MigrationExecutionException>(() => OriginalMigrationDocumentReader.Read<BackupReceipt>(tooLarge));
        Assert.Contains("too large", size.Message);
        string tooDeep = new string('[', 65) + "0" + new string(']', 65);
        _ = Assert.Throws<MigrationExecutionException>(() => OriginalMigrationDocumentReader.Read<BackupReceipt>(tooDeep));
    }

    private static string[] Originals(InitialMigrationAdmissionPayload payload)
    {
        return [payload.OriginalBackupReceiptJson, payload.OriginalSchemaPlanJson, payload.OriginalAuthorizationJson, payload.OriginalVerifiedRestoreReceiptJson];
    }
}

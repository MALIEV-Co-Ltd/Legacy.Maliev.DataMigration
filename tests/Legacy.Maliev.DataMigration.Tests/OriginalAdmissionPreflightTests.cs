namespace Legacy.Maliev.DataMigration.Tests;

public sealed class OriginalAdmissionPreflightTests
{
    [Fact]
    public async Task OriginalInputPreflight_ValidatesWithoutBindingOrSigningButDoesNotRefreshHistoricalAuthority()
    {
        using RecoveryAuthorityTestData data = await RecoveryAuthorityTestData.CreateAsync();
        InitialMigrationAdmissionPayload original = data.AdmissionPayload;
        data.Verifier.ValidateOriginalInputs(original.OriginalBackupReceiptJson, original.OriginalSchemaPlanJson,
            original.OriginalAuthorizationJson, original.OriginalVerifiedRestoreReceiptJson, data.AdmittedAt);
        _ = Assert.Throws<MigrationExecutionException>(() => data.Verifier.ValidateOriginalInputs(original.OriginalBackupReceiptJson,
            original.OriginalSchemaPlanJson, original.OriginalAuthorizationJson, original.OriginalVerifiedRestoreReceiptJson, data.Now));
        data.Verifier.ValidateAdmission(data.Admission, data.Now);
        _ = Assert.Throws<MigrationExecutionException>(() => data.Verifier.ValidateInitialAcquisition(data.Admission, data.Source, data.Binding, data.Now));
    }

    [Theory]
    [InlineData("backup")]
    [InlineData("plan")]
    [InlineData("authorization")]
    [InlineData("restore")]
    public async Task OriginalInputPreflight_RejectsMalformedOriginals(string kind)
    {
        using RecoveryAuthorityTestData data = await RecoveryAuthorityTestData.CreateAsync();
        InitialMigrationAdmissionPayload original = data.AdmissionPayload;
        _ = Assert.Throws<MigrationExecutionException>(() => data.Verifier.ValidateOriginalInputs(
            kind == "backup" ? "{}" : original.OriginalBackupReceiptJson,
            kind == "plan" ? "{}" : original.OriginalSchemaPlanJson,
            kind == "authorization" ? "{}" : original.OriginalAuthorizationJson,
            kind == "restore" ? "{}" : original.OriginalVerifiedRestoreReceiptJson, data.AdmittedAt));
    }
}

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class ApprovedIdentityLockoutEndPrecisionTests
{
    [Theory]
    [InlineData("CustomerIdentity", true)]
    [InlineData("EmployeeIdentity", true)]
    [InlineData("Customer", false)]
    [InlineData("Employee", false)]
    public void Applies_OnlyReviewedIdentityDatabases(string database, bool expected)
    {
        Assert.Equal(expected, ApprovedIdentityLockoutEndPrecision.Applies(
            database, "dbo", "AspNetUsers", "LockoutEnd", "datetimeoffset(7)",
            "timestamp with time zone"));
    }

    [Theory]
    [InlineData("dbo", "AspNetUsers", "LockoutEnd", "datetimeoffset(6)", "timestamp with time zone")]
    [InlineData("dbo", "AspNetUsers", "LockoutEnd", "datetimeoffset(7)", "text")]
    [InlineData("dbo", "AspNetUsers", "CreatedAt", "datetimeoffset(7)", "timestamp with time zone")]
    [InlineData("public", "AspNetUsers", "LockoutEnd", "datetimeoffset(7)", "timestamp with time zone")]
    public void Applies_RejectsOtherColumnContracts(
        string schema, string table, string column, string sourceType, string targetType)
    {
        Assert.False(ApprovedIdentityLockoutEndPrecision.Applies(
            "CustomerIdentity", schema, table, column, sourceType, targetType));
    }
}

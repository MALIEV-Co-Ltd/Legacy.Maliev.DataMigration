namespace Legacy.Maliev.DataMigration;

/// <summary>
/// The two ASP.NET Identity runtime columns remain PostgreSQL timestamps. Their exact SQL Server
/// datetimeoffset(7) values require a companion capture before any row synchronization because
/// PostgreSQL timestamps retain only microseconds.
/// </summary>
public static class ApprovedIdentityLockoutEndPrecision
{
    public const string TargetType = "timestamp with time zone";
    public const string SourceType = "datetimeoffset(7)";

    public static bool Applies(string database, string sourceSchema, string sourceTable,
        string column, string sourceType, string targetType)
    {
        return database is "CustomerIdentity" or "EmployeeIdentity" &&
               sourceSchema == "dbo" && sourceTable == "AspNetUsers" &&
               column == "LockoutEnd" && sourceType == SourceType && targetType == TargetType;
    }
}

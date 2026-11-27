using System.Text.Json;
using Microsoft.Data.SqlClient;

namespace Legacy.Maliev.DataMigration.Console;

/// <summary>Fixed read-only SQL Server capture; each database keeps its actual independent snapshot window.</summary>
internal static class CurrentAuthArchiveFinal6SourceCapture
{
    // Neither a deserialized capture nor a profile selector can construct this live holder.
    internal sealed class Captured
    {
        internal CurrentAuthArchiveFinal6SourceEvidence Evidence { get; }
        internal CurrentAuthArchiveFinal6Audience Audience { get; }
        private readonly CurrentAuthArchivePins _pins;
        private readonly IReceiptAttestationTrustStore _trust;
        private readonly CurrentAuthArchiveClaim _claim;
        private Captured(CurrentAuthArchiveFinal6SourceEvidence evidence, CurrentAuthArchiveFinal6Audience audience,
            CurrentAuthArchivePins pins, IReceiptAttestationTrustStore trust, CurrentAuthArchiveClaim claim)
        { Evidence = evidence; Audience = audience; _pins = pins; _trust = trust; _claim = claim; }

        internal async Task RequireAsync(CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            CurrentAuthLocalSessionArchivePolicy.RequirePins(_pins, _trust);
            var audience = Verify(_claim, _pins, _trust, DateTimeOffset.UtcNow);
            if (audience != Audience || await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false) != audience.AcceptedCommitSha)
            { throw CurrentAuthArchiveFinal6Source.Invalid(); }
            CurrentAuthArchiveFinal6Source.Require(Evidence, audience.AcceptedCommitSha, audience.SourceIdentitySha256,
                audience.SourceDefinitionSha256, DateTimeOffset.UtcNow);
        }

        internal static async Task<Captured> CaptureAsync(string protectedSourceConnection, CurrentAuthArchiveClaim audienceClaim,
            CurrentAuthArchivePins pins, IReceiptAttestationTrustStore trust, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            // Authenticate the distinct signed audience before any SQL connection is attempted.
            CurrentAuthLocalSessionArchivePolicy.RequirePins(pins, trust);
            var audience = Verify(audienceClaim, pins, trust, DateTimeOffset.UtcNow);
            var actual = await CaptureActualAsync(protectedSourceConnection, audience.SourceIdentitySha256, audience.AcceptedCommitSha, ct).ConfigureAwait(false);
            var result = new Captured(new(CurrentAuthArchiveFinal6Source.Kind, actual), audience, pins, trust, audienceClaim);
            await result.RequireAsync(ct).ConfigureAwait(false); return result;
        }
    }

    private static CurrentAuthArchiveFinal6Audience Verify(CurrentAuthArchiveClaim claim, CurrentAuthArchivePins pins,
        IReceiptAttestationTrustStore trust, DateTimeOffset now)
    {
        var audience = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveFinal6Audience>(claim,
            CurrentAuthArchiveFinal6AudiencePolicy.Domain, pins.ReviewKeyId, pins.ReviewFingerprint, trust);
        CurrentAuthArchiveFinal6AudiencePolicy.Require(audience, pins, now);
        return audience.CoreImageSha256 != CurrentAuthTypedHostProducer.ImageHash(typeof(CurrentAuthRepairPermit).Assembly.Location) ||
            audience.ConsoleImageSha256 != CurrentAuthTypedHostProducer.ImageHash(typeof(MigrationConsole).Assembly.Location)
            ? throw CurrentAuthArchiveFinal6Source.Invalid()
            : audience;
    }

    private static async Task<CurrentAuthArchiveRecoverySourceEvidence> CaptureActualAsync(string sourceConnection,
        string independentlyExpectedSourceIdentitySha256, string acceptedCommit, CancellationToken ct)
    {
        if (System.Reflection.Assembly.GetEntryAssembly() != typeof(CurrentAuthArchiveFinal6SourceCapture).Assembly ||
            await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false) != acceptedCommit ||
            !CurrentAuthRepairPermit.HashShape(independentlyExpectedSourceIdentitySha256))
        { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        var endpoint = new SqlConnectionStringBuilder(sourceConnection)
        { ApplicationIntent = ApplicationIntent.ReadOnly, Pooling = false, ConnectTimeout = 15, ApplicationName = "Legacy.Maliev.AuthArchiveFinal6.ReadOnlyProofCapture" };
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromMinutes(2));
        DateTimeOffset began = DateTimeOffset.UtcNow;
        string before = await ObserveIdentityAsync(endpoint.ConnectionString, deadline.Token).ConfigureAwait(false);
        if (before != independentlyExpectedSourceIdentitySha256) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        await using var source = new SqlServerMigrationSource(new SqlServerMigrationSourceOptions(endpoint.ConnectionString)
        {
            // This fixed factory captures Final6 directly; it never rewrites a phase3 plan.
            ConsumerOverlays = ConsumerOverlaySelection.CurrentConsumerSchemaV3CompanyStorageSourceOrder,
            ContactRequestCollationProfile = ContactRequestCollationProfile.ExplicitC,
        });
        var measured = new MeasuredSource(source);
        FreshSchemaPlan plan = await FreshSchemaPlanProducer.ProduceAsync(measured, acceptedCommit, DateTimeOffset.UtcNow, deadline.Token).ConfigureAwait(false);
        string after = await ObserveIdentityAsync(endpoint.ConnectionString, deadline.Token).ConfigureAwait(false);
        if (before != after) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        DateTimeOffset completed = DateTimeOffset.UtcNow;
        CurrentAuthArchiveFinal6Source.RequireProfiles(plan, completed);
        return new(plan, SchemaPlanCanonicalizer.ComputeSha256(plan), before, SourceCatalogDefinitionFingerprintV1.Compute(plan, acceptedCommit, before, completed), began, completed, measured.Windows.ToArray());
    }

    private static async Task<string> ObserveIdentityAsync(string sourceConnection, CancellationToken ct)
    {
        var endpoint = new SqlConnectionStringBuilder(sourceConnection) { InitialCatalog = "master", Pooling = false };
        await using var connection = new SqlConnection(endpoint.ConnectionString); await connection.OpenAsync(ct).ConfigureAwait(false);
        // Server/database identity, not client connection identity. No production rows are read or retained.
        const string sql = """
            SELECT CONVERT(nvarchar(128),SERVERPROPERTY('ServerName')),
                   CONVERT(int,SERVERPROPERTY('EngineEdition')),d.name,d.service_broker_guid,
                   r.database_guid,d.collation_name
            FROM sys.databases d JOIN sys.database_recovery_status r ON r.database_id=d.database_id
            WHERE d.name IN ('ContactRequest','Country','Currency','Customer','CustomerIdentity','DataProtectionKeys',
              'DataProtectionKeysEmployee','Employee','EmployeeIdentity','Invoice','JobOffers','LocationData','Material',
              'Message','Order','OrderStatus','Payment','PurchaseOrder','Quotation','QuotationRequest','Receipt','Supplier','Upload')
            ORDER BY d.name COLLATE Latin1_General_100_BIN2;
            """;
        await using var command = new SqlCommand(sql, connection) { CommandTimeout = 15 };
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        var rows = new List<object>(); var names = new List<string>();
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            string name = reader.GetString(2); Guid database = reader.GetGuid(4);
            if (database == Guid.Empty) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
            names.Add(name); rows.Add(new
            {
                Server = reader.GetString(0),
                EngineEdition = reader.GetInt32(1),
                Database = name,
                Broker = reader.GetGuid(3),
                DatabaseGuid = database,
                Collation = reader.GetString(5)
            });
        }
        return !names.SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal)
            ? throw CurrentAuthArchiveFinal6Source.Invalid()
            : CurrentAuthLocalSessionArchivePolicy.HashBytes([.. "Legacy.Maliev.ConsumerColumnBootstrap.SqlSourceIdentity.v1\0"u8,
            .. JsonSerializer.SerializeToUtf8Bytes(rows)]);
    }

    private sealed class MeasuredSource(IDatabaseSchemaPlanSource actual) : IDatabaseSchemaPlanSource
    {
        private readonly List<CurrentAuthArchiveRecoverySourceWindow> _windows = [];
        private string? _database;
        private DateTimeOffset _requested, _opened;
        internal IReadOnlyList<CurrentAuthArchiveRecoverySourceWindow> Windows => _windows.AsReadOnly();
        public async Task BeginDatabaseSnapshotAsync(string database, CancellationToken ct)
        {
            if (_database is not null) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
            _database = database; _requested = DateTimeOffset.UtcNow;
            await actual.BeginDatabaseSnapshotAsync(database, ct).ConfigureAwait(false); _opened = DateTimeOffset.UtcNow;
        }
        public Task<DatabaseSchemaPlan> GenerateDatabasePlanAsync(string database, CancellationToken ct)
        {
            return _database != database ? throw CurrentAuthArchiveFinal6Source.Invalid() : actual.GenerateDatabasePlanAsync(database, ct);
        }
        public async Task CompleteDatabaseSnapshotAsync(string database, CancellationToken ct)
        {
            if (_database != database) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
            await actual.CompleteDatabaseSnapshotAsync(database, ct).ConfigureAwait(false);
            _windows.Add(new(database, _requested, _opened, DateTimeOffset.UtcNow)); _database = null;
        }
        public async Task RollbackDatabaseSnapshotAsync(string database, CancellationToken ct)
        {
            if (_database != database) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
            await actual.RollbackDatabaseSnapshotAsync(database, ct).ConfigureAwait(false); _database = null;
        }
    }
}

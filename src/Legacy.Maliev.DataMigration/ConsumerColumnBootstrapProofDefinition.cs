using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

internal sealed record ConsumerColumnBootstrapProofCohort(int ServerVersion, string ImageReference)
{
    internal static ConsumerColumnBootstrapProofCohort PostgreSql184 { get; } = new(180004,
        "postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382");
    internal static ConsumerColumnBootstrapProofCohort PostgreSql187 { get; } = new(180007,
        "postgres@sha256:68e33adb18d9962952f00d5e3b8644305e10e375f98dd652bf6ee6a1836314ba");
    internal void Require()
    {
        if (this != PostgreSql184 && this != PostgreSql187) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
    }
}

/// <summary>A new proof-only definition domain. Full source plans are never rewritten or rehashed as fresh evidence.</summary>
internal static class ConsumerColumnBootstrapProofDefinition
{
    internal static string Compute(FreshSchemaPlan source, string sourceIdentitySha256, string runnerSha256,
        ConsumerColumnBootstrapProofCohort cohort, DateTimeOffset actualInvocationUtc)
    {
        cohort.Require();
        if (!ConsumerColumnBootstrapOperationalContract.IsHash(sourceIdentitySha256) || !ConsumerColumnBootstrapOperationalContract.IsHash(runnerSha256))
        { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        var contract = ConsumerColumnBootstrapContract.Create(source, source.SourceCommitSha, actualInvocationUtc);
        // SourceSchemaSha256 and SourceColumns.MetadataSha256 already replace SQL identity last_value
        // with <identity-current> in SqlServerMigrationSource.ResolveSchemaHashValue. Keep both complete
        // definition hashes. Omit only capture time and identity CurrentValue/IsCalled;
        // retain SourceKnownEmpty and MaxObservedDataLength because they affect eligibility.
        var definition = new
        {
            Kind = "consumer-column-bootstrap-definition-v1",
            source.SourceCommitSha,
            SourceIdentitySha256 = sourceIdentitySha256,
            RunnerSha256 = runnerSha256,
            Cohort = cohort,
            CompleteSourceDefinitionSha256 = SourceCatalogDefinitionFingerprintV1.Compute(source, source.SourceCommitSha, sourceIdentitySha256, actualInvocationUtc),
            Operands = ConsumerColumnBootstrapContract.Operands(),
            OwnerServiceContractsSha256 = ApprovedCurrentConsumerSchemaManifest.ServiceContractsSha256,
            Physical = ConsumerColumnBootstrapOperationalContract.Databases.Select(database => new
            {
                Database = database,
                Before = contract.Before(database).Tables.Select(ProjectPhysicalTable).ToArray(),
                After = contract.After(database).Tables.Select(ProjectPhysicalTable).ToArray(),
                CandidateSha256 = ConsumerColumnBootstrapOperationalContract.Hash(Encoding.UTF8.GetBytes(ConsumerColumnBootstrapContract.CandidateSql(database))),
            }).ToArray(),
        };
        return ConsumerColumnBootstrapOperationalContract.Hash([.. "Legacy.Maliev.ConsumerColumnBootstrap.Definition.v1\0"u8,
            .. JsonSerializer.SerializeToUtf8Bytes(definition)]);
    }

    // Owner-owned PostgreSQL identities have no SQL Server source declaration. Keep their
    // physical model definitions separately; full native sequence state remains in the pins.
    internal static object ProjectPhysicalTable(TableCopyPlan table)
    {
        return new
        {
            Table = SourceCatalogDefinitionFingerprintV1.ProjectTable(table with { Identities = [] }),
            IdentityDefinitions = table.Identities.Select(identity => new
            { identity.Column, identity.SeedValue, identity.IncrementValue }).ToArray(),
        };
    }
}

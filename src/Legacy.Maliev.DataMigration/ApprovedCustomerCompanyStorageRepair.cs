using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

internal sealed record CustomerCompanyStorageRepairOwner(string Head, bool Clean, DateTimeOffset ObservedAtUtc,
    IReadOnlyDictionary<string, string> Files);

/// <summary>
/// Pure fixed preparation and disposable characterization input only. This is not an execution permit,
/// an operational preservation verifier, a signed receipt or authority to alter a persistent database.
/// </summary>
internal sealed class ApprovedCustomerCompanyStorageRepair
{
    internal const string OwnerHead = "439f34c15b5535df0554618b3ef7bdc9deae491b";
    // Independently fetched UTF8 GitHub contents at OwnerHead on 2026-11-24; hashes cover exact bytes.
    // https://github.com/MALIEV-Co-Ltd/Legacy.Maliev.CustomerService/tree/439f34c15b5535df0554618b3ef7bdc9deae491b
    private static readonly Dictionary<string, string> OwnerPins =
        new(StringComparer.Ordinal)
        {
            ["Legacy.Maliev.CustomerService.Data/CustomerDbContext.cs"] = "4f33a8c15cc5b1241ee42327a4945260c775e3c3d34939ab85f29afa8963c82f",
            ["Legacy.Maliev.CustomerService.Data/Migrations/CustomerDbContextModelSnapshot.cs"] = "208f45fa79c738fed5e9b5151b92e7185342141ad96415d5e3b4213232f21750",
            ["Legacy.Maliev.CustomerService.Data/Migrations/20261024150000_EnforceCompanySourceStorage.cs"] = "6f5f3dd97d809ebddca5c4fdc98041fbb4388a70a529d0d165c3d5bb17ab2db5",
            ["Legacy.Maliev.CustomerService.Data/CompanySourceConstraints.cs"] = "7834a0a588e10c079e6f85e27dd8d47c8b905ddc77f328748955ae155898942f",
        };
    private readonly DatabaseSchemaPlan _before;
    private readonly DatabaseSchemaPlan _after;
    private readonly string _digest;

    private ApprovedCustomerCompanyStorageRepair(DatabaseSchemaPlan before, DatabaseSchemaPlan after, string sourceCommitSha)
    {
        _before = before;
        _after = after;
        _digest = Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new
        {
            Domain = "Legacy.Maliev.CustomerCompanyStorage.Preparation.v1",
            SourceCommitSha = sourceCommitSha,
            OwnerHead,
            OwnerPins,
            Before = before,
            After = after,
            CandidateSqlSha256 = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(CandidateSql.Replace("\r\n", "\n", StringComparison.Ordinal)))),
            Limitation = "pure-preparation-no-operational-preservation-or-execution-authority",
        })));
    }

    internal static ApprovedCustomerCompanyStorageRepair Create(DatabaseSchemaPlan before, string sourceCommitSha,
        string independentlyAcceptedSourceCommitSha, CustomerCompanyStorageRepairOwner owner, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(before);
        ArgumentNullException.ThrowIfNull(owner);
        if (sourceCommitSha.Length != 40 || !sourceCommitSha.All(IsLowerHex) ||
            sourceCommitSha != independentlyAcceptedSourceCommitSha || before.Database != "Customer" ||
            before.TargetExtensionProfile != ApprovedCurrentConsumerSchemaManifest.Customer ||
            before.SourceDispositionProfile is not null || before.SourceTableDispositions.Count != 0 ||
            before.SourceSchemaSha256.Length != 64 || !before.SourceSchemaSha256.All(IsLowerHex) ||
            before.TargetSchemaSha256 != PostgreSqlSchemaFingerprint.ComputeExpected(before) ||
            owner.Head != OwnerHead || !owner.Clean || nowUtc.Offset != TimeSpan.Zero ||
            owner.ObservedAtUtc.Offset != TimeSpan.Zero || owner.ObservedAtUtc > nowUtc ||
            nowUtc - owner.ObservedAtUtc > TimeSpan.FromHours(2) || owner.Files.Count != OwnerPins.Count ||
            OwnerPins.Any(x => owner.Files.GetValueOrDefault(x.Key) != x.Value))
        { throw Invalid(); }
        before = Clone(before);
        DatabaseSchemaPlan after = before with { TargetExtensionProfile = CustomerCompanyStorageManifest.Profile };
        // The appended manifest independently checks the old Company types/nullability/defaults.
        after = after with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(after) };
        return new(before, after, sourceCommitSha);
    }

    internal DatabaseSchemaPlan Before()
    {
        return Clone(_before);
    }

    internal DatabaseSchemaPlan After()
    {
        return Clone(_after);
    }

    internal string ComputeSha256()
    {
        return _digest;
    }

    // Literal reviewed owner Up SQL through its validated checks. No row UPDATE, trimming or allocation reset.
    // Callers receive text only; this class intentionally has no database-provider execution method.
    internal static string CandidateSql => """
        SET LOCAL lock_timeout = '5s';
        SET LOCAL statement_timeout = '30s';
        LOCK TABLE public."Company" IN ACCESS EXCLUSIVE MODE;
        DO $guard$
        BEGIN
            IF current_setting('server_encoding') <> 'UTF8'
                OR (SELECT count(*) FROM pg_attribute WHERE attrelid = 'public."Company"'::regclass
                    AND attname IN ('Name','TaxNumber','Registrar') AND NOT attisdropped
                    AND attnotnull = (attname = 'Name') AND atttypid = 'varchar'::regtype AND atttypmod = 260) <> 3
                OR EXISTS (SELECT 1 FROM pg_attrdef d JOIN pg_attribute a ON a.attrelid = d.adrelid AND a.attnum = d.adnum
                    WHERE d.adrelid = 'public."Company"'::regclass AND a.attname IN ('Name','TaxNumber','Registrar') AND NOT a.attisdropped)
                OR EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'public."Company"'::regclass
                    AND conname IN ('CK_Company_Name_SourceLength','CK_Company_TaxNumber_SourceLength','CK_Company_Registrar_SourceLength'))
                OR EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = 'public."Company"'::regclass AND tgname = 'NormalizeCompanySource')
                OR EXISTS (SELECT 1 FROM pg_proc WHERE pronamespace = 'public'::regnamespace AND proname = 'NormalizeCompanySource') THEN
                RAISE EXCEPTION 'Company capacity upgrade schema is incompatible.';
            END IF;
            IF (SELECT count(*) FROM (SELECT 1 FROM public."Company" LIMIT 10001) bounded) > 10000 THEN
                RAISE EXCEPTION 'Company capacity upgrade row limit exceeded.';
            END IF;
            IF EXISTS (SELECT 1 FROM public."Company" WHERE
                char_length("Name") + char_length(regexp_replace("Name" COLLATE "C", U&'[\0001-\FFFF]', '', 'g')) > 256 OR
                char_length("TaxNumber") + char_length(regexp_replace("TaxNumber" COLLATE "C", U&'[\0001-\FFFF]', '', 'g')) > 256 OR
                char_length("Registrar") + char_length(regexp_replace("Registrar" COLLATE "C", U&'[\0001-\FFFF]', '', 'g')) > 256) THEN
                RAISE EXCEPTION 'Retained Company fields exceed source capacity.';
            END IF;
        END $guard$;
        DO $types$
        DECLARE alterations text; column_count integer;
        BEGIN
            SELECT string_agg(format('ALTER COLUMN %I TYPE text COLLATE %I.%I',
                a.attname,n.nspname,c.collname),', ' ORDER BY a.attnum),count(*)
            INTO alterations,column_count
            FROM pg_attribute a JOIN pg_collation c ON c.oid=a.attcollation
                JOIN pg_namespace n ON n.oid=c.collnamespace
            WHERE a.attrelid='public."Company"'::regclass AND NOT a.attisdropped
                AND a.attname IN ('Name','TaxNumber','Registrar');
            IF column_count <> 3 OR alterations IS NULL THEN
                RAISE EXCEPTION 'Company capacity collation metadata is incompatible.';
            END IF;
            EXECUTE 'ALTER TABLE public."Company" ' || alterations;
        END $types$;
        ALTER TABLE public."Company" ADD CONSTRAINT "CK_Company_Name_SourceLength" CHECK
            (char_length("Name") + char_length(regexp_replace("Name" COLLATE "C", U&'[\0001-\FFFF]', '', 'g')) <= 256) NOT VALID;
        ALTER TABLE public."Company" ADD CONSTRAINT "CK_Company_TaxNumber_SourceLength" CHECK
            (char_length("TaxNumber") + char_length(regexp_replace("TaxNumber" COLLATE "C", U&'[\0001-\FFFF]', '', 'g')) <= 256) NOT VALID;
        ALTER TABLE public."Company" ADD CONSTRAINT "CK_Company_Registrar_SourceLength" CHECK
            (char_length("Registrar") + char_length(regexp_replace("Registrar" COLLATE "C", U&'[\0001-\FFFF]', '', 'g')) <= 256) NOT VALID;
        ALTER TABLE public."Company" VALIDATE CONSTRAINT "CK_Company_Name_SourceLength",
            VALIDATE CONSTRAINT "CK_Company_TaxNumber_SourceLength", VALIDATE CONSTRAINT "CK_Company_Registrar_SourceLength";
        """ + "\n" + CustomerCompanyStorageManifest.CreateNormalizerSql;

    private static bool IsLowerHex(char value)
    {
        return value is (>= '0' and <= '9') or (>= 'a' and <= 'f');
    }

    private static T Clone<T>(T value)
    {
        return JsonSerializer.Deserialize<T>(JsonSerializer.SerializeToUtf8Bytes(value)) ?? throw Invalid();
    }

    private static MigrationExecutionException Invalid()
    {
        return new("customer_company_storage_repair_preparation_invalid",
        "The fixed Company storage preparation requires exact source, owner and physical-plan bindings.");
    }
}

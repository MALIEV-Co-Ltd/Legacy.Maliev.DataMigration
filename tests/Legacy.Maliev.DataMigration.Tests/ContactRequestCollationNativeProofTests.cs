using System.Data;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using Testcontainers.PostgreSql;

namespace Legacy.Maliev.DataMigration.Tests;

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class ContactRequestCollationNativeProofTestGroup
{
    public const string Name = "ContactRequest explicit C disposable proof";
}

/// <summary>Disposable feasibility proofs only. The DDL below is not a production repair provider or execution authority.</summary>
[Collection(ContactRequestCollationNativeProofTestGroup.Name)]
public sealed class ContactRequestCollationNativeProofTests
{
    private static readonly string[] SupportedLocales = ["en_US.utf8", "C"];
    [Theory]
    [InlineData("en_US.utf8")]
    [InlineData("C")]
    public async Task Contact_C_native_column_transition_preserves_rows_private_catalogs_and_sequence_and_rolls_back(string locale)
    {
        await using PostgreSqlContainer container = NewProofBuilder().Build();
        await container.StartAsync();
        string connectionString = await CreateDatabaseAsync(container.GetConnectionString(), locale);
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await BootstrapAsync(connection);
        DatabaseSchemaPlan original = WithHash(ContactRequestCollationTestSchema.CreateDraft());
        DatabaseSchemaPlan selected = WithHash(ApprovedContactRequestCollationManifest.Apply(original, ContactRequestCollationProfile.ExplicitC));
        Assert.Equal(original.TargetSchemaSha256, await InspectAsync(connection, original));
        string beforeEvidence = await PreservationEvidenceAsync(connection);
        string before = HashEvidence(beforeEvidence);
        string expectedSearch = await SearchResultsAsync(connection, explicitC: true);
        string databaseLocale = await ScalarAsync<string>(connection, "SELECT datcollate FROM pg_database WHERE datname=current_database();");
        Assert.Equal(locale, databaseLocale);

        _ = await Assert.ThrowsAsync<IOException>(() => RepairFixtureAsync(connection, original, selected, failAfterDdl: true));
        Assert.Equal(before, await PreservationShaAsync(connection));
        Assert.Equal(original.TargetSchemaSha256, await InspectAsync(connection, original));

        await RepairFixtureAsync(connection, original, selected, failAfterDdl: false);
        string afterEvidence = await PreservationEvidenceAsync(connection);
        AssertPreservedAfterReviewedRebuild(beforeEvidence, afterEvidence);
        AssertUnreviewedConstraintRebindingsRejected(beforeEvidence, afterEvidence);
        Assert.Equal(selected.TargetSchemaSha256, await InspectAsync(connection, selected));
        Assert.Equal(expectedSearch, await SearchResultsAsync(connection, explicitC: false));
        Assert.Equal(7L, await ScalarAsync<long>(connection, """
            SELECT count(*) FROM pg_attribute a
            WHERE a.attrelid='public."Message"'::regclass AND a.attnum BETWEEN 2 AND 8
              AND a.attcollation='pg_catalog."C"'::regcollation;
            """));
        Assert.Equal(databaseLocale, await ScalarAsync<string>(connection,
            "SELECT datcollate FROM pg_database WHERE datname=current_database();"));
        Assert.Equal(15L, await ScalarAsync<long>(connection, "SELECT count(*) FROM public.\"Message\";"));
        Assert.False(await ScalarAsync<bool>(connection, "SELECT 'é'::text COLLATE \"C\" = 'é'::text COLLATE \"C\";"));
        Assert.Equal(2L, await ScalarAsync<long>(connection,
            "SELECT count(*) FROM public.\"Message\" WHERE \"FirstName\" ILIKE 'alice';"));
        await AssertByteOrderAsync(connection);
    }

    [Fact]
    public async Task Contact_C_native_unreviewed_dependency_matrix_rejects_before_any_transition()
    {
        await using PostgreSqlContainer container = NewProofBuilder().Build();
        await container.StartAsync();
        string connectionString = await CreateDatabaseAsync(container.GetConnectionString(), "en_US.utf8");
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await BootstrapAsync(connection);
        string before = await PreservationShaAsync(connection);
        DatabaseSchemaPlan original = WithHash(ContactRequestCollationTestSchema.CreateDraft());
        string[] dependencyDdl =
        [
            "CREATE INDEX contact_text_index ON public.\"Message\" (\"FirstName\");",
            "CREATE INDEX contact_expression_index ON public.\"Message\" (lower(\"FirstName\"));",
            "ALTER TABLE public.\"Message\" ADD CONSTRAINT contact_unique UNIQUE (\"Email\");",
            "ALTER TABLE public.\"Message\" ADD CONSTRAINT contact_check CHECK (length(\"FirstName\") > 0);",
            "ALTER TABLE public.\"Message\" RENAME CONSTRAINT \"Message_FirstName_not_null\" TO contact_unreviewed_not_null;",
            "ALTER TABLE public.\"Message\" ALTER COLUMN \"FirstName\" DROP NOT NULL;",
            "ALTER TABLE public.\"Message\" ADD COLUMN contact_generated text GENERATED ALWAYS AS (lower(\"FirstName\")) STORED;",
            "CREATE VIEW public.contact_view AS SELECT \"FirstName\" FROM public.\"Message\";",
            "CREATE TABLE public.contact_reference (id integer REFERENCES public.\"Message\"(\"ID\"));",
            """
            CREATE FUNCTION public.contact_trigger() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$;
            CREATE TRIGGER contact_trigger BEFORE UPDATE ON public."Message" FOR EACH ROW EXECUTE FUNCTION public.contact_trigger();
            """,
        ];
        foreach (string ddl in dependencyDdl)
        {
            await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable);
            await ExecuteAsync(connection, ddl, transaction);
            // This is a test prerequisite for the future helper, not a new runtime authority factory.
            _ = await Assert.ThrowsAsync<InvalidOperationException>(() => RequireReviewedDependenciesAsync(connection, transaction));
            Assert.Equal(0L, await ScalarAsync<long>(connection, """
                SELECT count(*) FROM pg_attribute WHERE attrelid='public."Message"'::regclass
                  AND attnum BETWEEN 2 AND 8 AND attcollation='pg_catalog."C"'::regcollation;
                """, transaction));
            await transaction.RollbackAsync();
        }
        Assert.Equal(before, await PreservationShaAsync(connection));
        Assert.Equal(original.TargetSchemaSha256, await InspectAsync(connection, original));
    }

    private static DatabaseSchemaPlan WithHash(DatabaseSchemaPlan plan)
    {
        return plan with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(plan) };
    }

    private static PostgreSqlBuilder NewProofBuilder()
    {
        return new PostgreSqlBuilder("postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382")
            .WithEnvironment("POSTGRES_INITDB_ARGS", "--encoding=UTF8 --locale=en_US.utf8")
            .WithCreateParameterModifier(parameters =>
            {
                parameters.HostConfig!.Memory = 384 * 1024 * 1024;
                parameters.HostConfig.MemorySwap = 384 * 1024 * 1024;
                parameters.HostConfig.NanoCPUs = 500000000;
                foreach (IList<Docker.DotNet.Models.PortBinding> bindings in parameters.HostConfig.PortBindings!.Values)
                {
                    foreach (Docker.DotNet.Models.PortBinding binding in bindings) { binding.HostIP = "127.0.0.1"; }
                }
            });
    }

    private static async Task<string> CreateDatabaseAsync(string administrativeConnection, string locale)
    {
        Assert.Contains(locale, SupportedLocales);
        await using var connection = new NpgsqlConnection(administrativeConnection);
        await connection.OpenAsync();
        await ExecuteAsync(connection, $"CREATE DATABASE \"ContactRequest\" TEMPLATE template0 ENCODING 'UTF8' LOCALE_PROVIDER libc LC_COLLATE '{locale}' LC_CTYPE '{locale}';");
        return new NpgsqlConnectionStringBuilder(administrativeConnection) { Database = "ContactRequest", Pooling = false }.ConnectionString;
    }

    private static async Task BootstrapAsync(NpgsqlConnection connection)
    {
        await ExecuteAsync(connection, """
            CREATE TABLE public."Message" (
                "ID" integer GENERATED BY DEFAULT AS IDENTITY NOT NULL,
                "FirstName" character varying(50) NOT NULL,
                "LastName" character varying(50) NOT NULL,
                "Email" character varying(50) NOT NULL,
                "Company" character varying(50), "Telephone" character varying(50),
                "MessageContent" text NOT NULL, "Country" character varying(50) NOT NULL,
                "CreatedDate" timestamp without time zone DEFAULT timezone('UTC'::text, CURRENT_TIMESTAMP),
                "ModifiedDate" timestamp without time zone DEFAULT timezone('UTC'::text, CURRENT_TIMESTAMP),
                CONSTRAINT "PK_Message" PRIMARY KEY ("ID"));
            COMMENT ON TABLE public."Message" IS 'synthetic retained table comment';
            COMMENT ON COLUMN public."Message"."FirstName" IS 'synthetic retained column comment';
            COMMENT ON CONSTRAINT "Message_FirstName_not_null" ON public."Message" IS 'synthetic retained constraint comment';
            CREATE ROLE contact_reader NOLOGIN;
            GRANT SELECT ON public."Message" TO contact_reader;
            CREATE SCHEMA legacy_migration_internal;
            CREATE TABLE legacy_migration_internal.retained_history (id bigint PRIMARY KEY, effect text NOT NULL);
            INSERT INTO legacy_migration_internal.retained_history VALUES (1,'journal'),(2,'receipt'),(3,'empty-marker-boundary');
            COMMENT ON TABLE legacy_migration_internal.retained_history IS 'synthetic retained private comment';
            """);
        string[] values = ["Alice", "ALICE", "éclair", "Éclair", "é", "I", "i", "İ", "ı", "ß", "SS", "สวัสดี", "😀", "Z", "z"];
        for (int index = 0; index < values.Length; index++)
        {
            await using var command = new NpgsqlCommand("""
                INSERT INTO public."Message" ("FirstName","LastName","Email","Company","Telephone","MessageContent","Country","CreatedDate","ModifiedDate")
                VALUES (@value,@value,@email,NULL,NULL,@content,'TH',timestamp '2026-10-03 00:00:00.123456',NULL);
                """, connection);
            _ = command.Parameters.AddWithValue("value", values[index]);
            _ = command.Parameters.AddWithValue("email", $"synthetic-{index}@test.invalid");
            _ = command.Parameters.AddWithValue("content", "ข้อความ " + values[index]);
            _ = await command.ExecuteNonQueryAsync();
        }
        await ExecuteAsync(connection, "ALTER SEQUENCE public.\"Message_ID_seq\" CACHE 7;");
    }

    private static async Task RepairFixtureAsync(NpgsqlConnection connection, DatabaseSchemaPlan original,
        DatabaseSchemaPlan selected, bool failAfterDdl)
    {
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable);
        await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
        await ExecuteAsync(connection, "LOCK TABLE public.\"Message\" IN ACCESS EXCLUSIVE MODE;", transaction);
        await RequireReviewedDependenciesAsync(connection, transaction);
        Assert.Equal(original.TargetSchemaSha256, await inspector.InspectSchemaAsync(original, CancellationToken.None));
        string alterations = string.Join(", ", selected.Tables[0].OrderedColumns.Where(column => selected.Tables[0].Collations.ContainsKey(column))
            .Select(column => $"ALTER COLUMN \"{column}\" TYPE {selected.Tables[0].ColumnTypes[column]} COLLATE \"C\""));
        await ExecuteAsync(connection, "ALTER TABLE public.\"Message\" " + alterations + ";", transaction);
        Assert.Equal(selected.TargetSchemaSha256, await inspector.InspectSchemaAsync(selected, CancellationToken.None));
        if (failAfterDdl)
        {
            await transaction.RollbackAsync();
            throw new IOException("Synthetic late failure after all seven column alterations.");
        }
        await transaction.CommitAsync();
    }

    private static async Task RequireReviewedDependenciesAsync(NpgsqlConnection connection, NpgsqlTransaction transaction)
    {
        bool drift = await ScalarAsync<bool>(connection, """
            SELECT EXISTS (SELECT 1 FROM pg_index WHERE indrelid='public."Message"'::regclass AND NOT indisprimary)
              OR EXISTS (SELECT 1 FROM pg_constraint WHERE (conrelid='public."Message"'::regclass OR confrelid='public."Message"'::regclass) AND contype NOT IN ('p','n'))
              OR EXISTS (SELECT 1 FROM pg_constraint k WHERE conrelid='public."Message"'::regclass AND contype='n'
                AND (NOT convalidated OR NOT conenforced OR cardinality(conkey)<>1 OR conkey[1] NOT IN (1,2,3,4,7,8)
                  OR conname <> (SELECT 'Message_'||a.attname||'_not_null' FROM pg_attribute a WHERE a.attrelid=k.conrelid AND a.attnum=k.conkey[1])))
              OR (SELECT count(*) FROM pg_constraint WHERE conrelid='public."Message"'::regclass AND contype='n') <> 6
              OR EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid='public."Message"'::regclass AND attnum>0 AND attgenerated<>'')
              OR EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid='public."Message"'::regclass AND NOT tgisinternal)
              OR EXISTS (SELECT 1 FROM pg_depend WHERE refobjid='public."Message"'::regclass AND classid='pg_rewrite'::regclass);
            """, transaction);
        if (drift)
        {
            throw new InvalidOperationException("Synthetic fixture contains an unreviewed PostgreSQL dependency.");
        }
    }

    private static async Task<string> InspectAsync(NpgsqlConnection connection, DatabaseSchemaPlan plan)
    {
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead);
        await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
        string result = await inspector.InspectSchemaAsync(plan, CancellationToken.None);
        await transaction.RollbackAsync();
        return result;
    }

    private static async Task<string> PreservationShaAsync(NpgsqlConnection connection)
    {
        return HashEvidence(await PreservationEvidenceAsync(connection));
    }

    private static string HashEvidence(string evidence)
    {
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(evidence))).ToLowerInvariant();
    }

    private static void AssertPreservedAfterReviewedRebuild(string before, string after)
    {
        JsonObject oldRoot = JsonNode.Parse(before)!.AsObject();
        Assert.Empty(oldRoot["reviewedCollationDependencies"]!.AsArray());
        Assert.Empty(JsonNode.Parse(after)!["reviewedCollationDependencies"]!.AsArray());
        JsonObject newRoot = NormalizeReviewedConstraintRebuild(oldRoot, JsonNode.Parse(after)!.AsObject());
        Assert.True(JsonNode.DeepEquals(oldRoot, newRoot), DescribePreservationDrift(oldRoot.ToJsonString(), newRoot.ToJsonString()));
    }

    private static JsonObject NormalizeReviewedConstraintRebuild(JsonObject before, JsonObject after)
    {
        JsonObject oldRoot = before.DeepClone().AsObject();
        JsonObject newRoot = after.DeepClone().AsObject();
        string messageOid = oldRoot["messageOid"]!.GetValue<string>();
        string constraintClass = oldRoot["constraintClassOid"]!.GetValue<string>();
        string relationClass = oldRoot["relationClassOid"]!.GetValue<string>();
        Require(oldRoot["messageOid"]!.ToJsonString() == newRoot["messageOid"]!.ToJsonString() &&
            oldRoot["constraintClassOid"]!.ToJsonString() == newRoot["constraintClassOid"]!.ToJsonString() &&
            oldRoot["relationClassOid"]!.ToJsonString() == newRoot["relationClassOid"]!.ToJsonString());
        JsonArray oldConstraints = oldRoot["constraints"]!.AsArray();
        JsonArray newConstraints = newRoot["constraints"]!.AsArray();
        string[] oldOids = oldConstraints.Select(node => node!["oid"]!.GetValue<string>()).ToArray();
        string[] newOids = newConstraints.Select(node => node!["oid"]!.GetValue<string>()).ToArray();
        Require(oldOids.Distinct(StringComparer.Ordinal).Count() == oldOids.Length &&
            newOids.Distinct(StringComparer.Ordinal).Count() == newOids.Length);
        foreach (int attnum in new[] { 2, 3, 4, 7, 8 })
        {
            JsonObject Find(JsonArray constraints)
            {
                JsonObject[] matches = constraints.Select(node => node!.AsObject()).Where(constraint =>
                    constraint["conrelid"]!.GetValue<string>() == messageOid && constraint["contype"]!.GetValue<string>() == "n" &&
                    constraint["conkey"]!.AsArray() is { Count: 1 } keys && keys[0]!.GetValue<int>() == attnum).ToArray();
                Require(matches.Length == 1 && matches[0]["convalidated"]!.GetValue<bool>() && matches[0]["conenforced"]!.GetValue<bool>());
                return matches[0];
            }
            JsonObject oldConstraint = Find(oldConstraints);
            JsonObject newConstraint = Find(newConstraints);
            string oldOid = oldConstraint["oid"]!.GetValue<string>();
            string newOid = newConstraint["oid"]!.GetValue<string>();
            Require(oldOid != newOid && !oldOids.Contains(newOid, StringComparer.Ordinal));
            JsonObject oldShape = oldConstraint.DeepClone().AsObject();
            JsonObject newShape = newConstraint.DeepClone().AsObject();
            _ = oldShape.Remove("oid"); _ = newShape.Remove("oid");
            Require(JsonNode.DeepEquals(oldShape, newShape));
            JsonObject Dependency(JsonObject root, string oid)
            {
                JsonObject[] matches = root["dependenciesExceptChangedCollations"]!.AsArray().Select(node => node!.AsObject())
                    .Where(dependency => dependency["classid"]!.GetValue<string>() == constraintClass &&
                        dependency["objid"]!.GetValue<string>() == oid).ToArray();
                Require(matches.Length == 1 && matches[0]["objsubid"]!.GetValue<int>() == 0 &&
                    matches[0]["refclassid"]!.GetValue<string>() == relationClass && matches[0]["refobjid"]!.GetValue<string>() == messageOid &&
                    matches[0]["refobjsubid"]!.GetValue<int>() == attnum && matches[0]["deptype"]!.GetValue<string>() == "a");
                return matches[0];
            }
            JsonObject oldDependency = Dependency(oldRoot, oldOid);
            JsonObject newDependency = Dependency(newRoot, newOid);
            newDependency["objid"] = oldOid;
            Require(JsonNode.DeepEquals(oldDependency, newDependency));
            newConstraint["oid"] = oldOid;
        }
        foreach (JsonObject root in new[] { before, newRoot })
        {
            foreach (string facet in new[] { "constraints", "dependenciesExceptChangedCollations" })
            {
                root[facet] = new JsonArray(root[facet]!.AsArray().Select(node => node!.DeepClone())
                    .OrderBy(node => node.ToJsonString(), StringComparer.Ordinal).ToArray());
            }
        }
        return newRoot;
    }

    private static void AssertUnreviewedConstraintRebindingsRejected(string before, string after)
    {
        foreach (string fault in new[] { "name", "validated", "enforced", "mapping", "oid-reuse", "dependency-column", "dependency-kind", "extra-dependency" })
        {
            JsonObject oldRoot = JsonNode.Parse(before)!.AsObject();
            JsonObject newRoot = JsonNode.Parse(after)!.AsObject();
            JsonObject constraint = newRoot["constraints"]!.AsArray().Select(node => node!.AsObject())
                .Single(node => node["conname"]!.GetValue<string>() == "Message_FirstName_not_null");
            JsonObject dependency = newRoot["dependenciesExceptChangedCollations"]!.AsArray().Select(node => node!.AsObject())
                .Single(node => node["classid"]!.GetValue<string>() == newRoot["constraintClassOid"]!.GetValue<string>() &&
                    node["objid"]!.GetValue<string>() == constraint["oid"]!.GetValue<string>());
            switch (fault)
            {
                case "name": constraint["conname"] = "unreviewed"; break;
                case "validated": constraint["convalidated"] = false; break;
                case "enforced": constraint["conenforced"] = false; break;
                case "mapping": constraint["conkey"] = new JsonArray(3); break;
                case "oid-reuse": constraint["oid"] = oldRoot["constraints"]![0]!["oid"]!.DeepClone(); break;
                case "dependency-column": dependency["refobjsubid"] = 3; break;
                case "dependency-kind": dependency["deptype"] = "n"; break;
                case "extra-dependency": newRoot["dependenciesExceptChangedCollations"]!.AsArray().Add(dependency.DeepClone()); break;
                default: throw new InvalidOperationException("Unknown synthetic mapping fault.");
            }
            _ = Assert.Throws<InvalidOperationException>(() => NormalizeReviewedConstraintRebuild(oldRoot, newRoot));
        }
    }

    private static void Require(bool condition)
    {
        if (!condition) { throw new InvalidOperationException("Unreviewed synthetic constraint or dependency mapping."); }
    }

    private static string DescribePreservationDrift(string before, string after)
    {
        using JsonDocument oldDocument = JsonDocument.Parse(before);
        using JsonDocument newDocument = JsonDocument.Parse(after);
        string[] changed = oldDocument.RootElement.EnumerateObject().Where(property =>
            property.Value.GetRawText() != newDocument.RootElement.GetProperty(property.Name).GetRawText())
            .Select(property => property.Name).ToArray();
        static string Constraints(JsonElement root)
        {
            return string.Join("; ", root.GetProperty("constraints").EnumerateArray().Select(constraint =>
                $"{constraint.GetProperty("conname").GetString()}:{constraint.GetProperty("oid").GetRawText()}:{constraint.GetProperty("conkey").GetRawText()}"));
        }
        return $"Changed preservation facets: {string.Join(", ", changed)}. Synthetic constraint mappings before [{Constraints(oldDocument.RootElement)}], after [{Constraints(newDocument.RootElement)}]. Collation dependencies before {oldDocument.RootElement.GetProperty("reviewedCollationDependencies").GetRawText()}, after {newDocument.RootElement.GetProperty("reviewedCollationDependencies").GetRawText()}.";
    }

    private static async Task<string> PreservationEvidenceAsync(NpgsqlConnection connection)
    {
        string evidence = await ScalarAsync<string>(connection, """
            SELECT jsonb_build_object(
                'messageOid','public."Message"'::regclass::oid::text,
                'constraintClassOid','pg_constraint'::regclass::oid::text,
                'relationClassOid','pg_class'::regclass::oid::text,
                'rows',(SELECT jsonb_agg(to_jsonb(m) ORDER BY "ID") FROM public."Message" m),
                'history',(SELECT jsonb_agg(to_jsonb(h) ORDER BY id) FROM legacy_migration_internal.retained_history h),
                'relations',(SELECT jsonb_agg(jsonb_build_array(c.oid,c.relname,c.relfilenode,c.relowner,c.relacl,c.reloptions,
                    c.reltype,c.relpersistence,obj_description(c.oid,'pg_class')) ORDER BY c.oid)
                    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('public','legacy_migration_internal')),
                'columnsExceptCollation',(SELECT jsonb_agg(jsonb_build_array(a.attrelid,a.attnum,a.attname,a.atttypid,a.atttypmod,
                    a.attnotnull,a.attidentity,a.attgenerated,a.attacl,col_description(a.attrelid,a.attnum),pg_get_expr(d.adbin,d.adrelid),
                    CASE WHEN a.attrelid='public."Message"'::regclass AND a.attnum BETWEEN 2 AND 8 THEN NULL ELSE a.attcollation END)
                    ORDER BY a.attrelid,a.attnum) FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid
                    JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
                    WHERE n.nspname IN ('public','legacy_migration_internal') AND a.attnum>0 AND NOT a.attisdropped),
                'constraints',(SELECT jsonb_agg(to_jsonb(k)||jsonb_build_object('retainedComment',obj_description(k.oid,'pg_constraint')) ORDER BY k.oid) FROM pg_constraint k JOIN pg_namespace n ON n.oid=k.connamespace
                    WHERE n.nspname IN ('public','legacy_migration_internal')),
                'indexes',(SELECT jsonb_agg(to_jsonb(i) ORDER BY i.indexrelid) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid
                    JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('public','legacy_migration_internal')),
                'types',(SELECT jsonb_agg(jsonb_build_array(to_jsonb(t),obj_description(t.oid,'pg_type')) ORDER BY t.oid)
                    FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname IN ('public','legacy_migration_internal')),
                'namespaces',(SELECT jsonb_agg(jsonb_build_array(to_jsonb(n),obj_description(n.oid,'pg_namespace')) ORDER BY n.oid)
                    FROM pg_namespace n WHERE n.nspname IN ('public','legacy_migration_internal')),
                'sequenceParameters',(SELECT to_jsonb(s) FROM pg_sequence s WHERE s.seqrelid='public."Message_ID_seq"'::regclass),
                'sequenceState',(SELECT jsonb_build_array(last_value,is_called) FROM public."Message_ID_seq"),
                'reviewedCollationDependencies',(SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY d.objsubid,d.refobjid,d.deptype),'[]'::jsonb)
                    FROM pg_depend d WHERE d.refclassid='pg_collation'::regclass AND d.classid='pg_class'::regclass
                        AND d.objid='public."Message"'::regclass AND d.objsubid BETWEEN 2 AND 8),
                'dependenciesExceptChangedCollations',(SELECT jsonb_agg(to_jsonb(d) ORDER BY d.classid,d.objid,d.objsubid,d.refclassid,d.refobjid,d.refobjsubid,d.deptype)
                    FROM pg_depend d WHERE (d.objid IN (SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                        WHERE n.nspname IN ('public','legacy_migration_internal')) OR d.refobjid='public."Message"'::regclass)
                    AND NOT (d.refclassid='pg_collation'::regclass AND d.classid='pg_class'::regclass
                        AND d.objid='public."Message"'::regclass AND d.objsubid BETWEEN 2 AND 8))
            )::text;
            """);
        return evidence;
    }

    private static Task<string> SearchResultsAsync(NpgsqlConnection connection, bool explicitC)
    {
        string expression = explicitC ? "\"FirstName\" COLLATE \"C\"" : "\"FirstName\"";
        return ScalarAsync<string>(connection, $$"""
            SELECT jsonb_agg(jsonb_build_array(pattern, ARRAY(SELECT "ID" FROM public."Message"
                WHERE {{expression}} ILIKE pattern ORDER BY "ID")) ORDER BY pattern COLLATE "C")::text
            FROM unnest(ARRAY['a%','é%','É%','i%','İ%','ß%','ส%','😀%']) AS patterns(pattern);
            """);
    }

    private static async Task AssertByteOrderAsync(NpgsqlConnection connection)
    {
        await using var command = new NpgsqlCommand("SELECT \"FirstName\" FROM public.\"Message\" ORDER BY \"FirstName\";", connection);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();
        var observed = new List<string>();
        while (await reader.ReadAsync())
        {
            observed.Add(reader.GetString(0));
        }
        Assert.Equal(observed.OrderBy(value => Convert.ToHexString(Encoding.UTF8.GetBytes(value)), StringComparer.Ordinal), observed);
    }

    private static async Task ExecuteAsync(NpgsqlConnection connection, string sql, NpgsqlTransaction? transaction = null)
    {
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        _ = await command.ExecuteNonQueryAsync();
    }

    private static async Task<T> ScalarAsync<T>(NpgsqlConnection connection, string sql, NpgsqlTransaction? transaction = null)
    {
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        return Assert.IsType<T>(await command.ExecuteScalarAsync());
    }
}

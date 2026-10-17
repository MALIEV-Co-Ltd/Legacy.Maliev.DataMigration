namespace Legacy.Maliev.DataMigration.Tests;

public sealed class ApprovedCurrentCustomerSequenceDefinitionTests
{
    internal static readonly DateTimeOffset Now = new(2026, 10, 13, 0, 0, 0, TimeSpan.Zero);
    internal static ApprovedCurrentCustomerSequenceDefinition Contract()
    {
        return ApprovedCurrentCustomerSequenceDefinition.Create(
        Source(), Owner(), new string('a', 40), Source().CatalogReportSha256, Now);
    }

    internal static CurrentCustomerSequenceSource Source()
    {
        return new(new string('a', 40),
            new string('c', 64), Now, 1000, 1, 69831);
    }

    internal static CurrentCustomerSequenceOwner Owner()
    {
        return new(ApprovedCurrentCustomerSequenceDefinition.CustomerOwnerHead,
            true, Now, ApprovedCurrentCustomerSequenceDefinition.ContextSha256, ApprovedCurrentCustomerSequenceDefinition.OwnerSnapshotSha256);
    }

    [Fact]
    public void Digest_is_deterministic_and_candidate_changes_definition_only()
    {
        Assert.Equal(Contract().ComputeSha256(), Contract().ComputeSha256());
        Assert.Equal("ALTER SEQUENCE public.\"Customer_ID_seq\" START WITH 1000;", ApprovedCurrentCustomerSequenceDefinition.CandidateSql);
        CurrentCustomerSequenceObservation before = Observation(State());
        ApprovedCurrentCustomerSequenceDefinition.RequirePreserved(before, Observation(Final(before.State)), "legacy_local");
        Assert.Equal(69831, before.State.LastValue);
    }

    [Theory]
    [InlineData("seed")]
    [InlineData("increment")]
    [InlineData("report")]
    [InlineData("source")]
    [InlineData("stale")]
    public void Unpinned_source_observations_are_rejected(string field)
    {
        CurrentCustomerSequenceSource source = field switch
        {
            "seed" => Source() with { Seed = 1 },
            "increment" => Source() with { Increment = 2 },
            "report" => Source() with { CatalogReportSha256 = new('b', 64) },
            "source" => Source() with { CommitSha = new('b', 40) },
            _ => Source() with { ObservedAtUtc = Now.AddHours(-13) },
        };
        _ = Assert.Throws<MigrationExecutionException>(() => ApprovedCurrentCustomerSequenceDefinition.Create(source, Owner(), new('a', 40), Source().CatalogReportSha256, Now));
    }

    [Theory]
    [InlineData("head")]
    [InlineData("dirty")]
    [InlineData("context")]
    [InlineData("snapshot")]
    public void Owner_source_is_independently_pinned(string field)
    {
        CurrentCustomerSequenceOwner owner = field switch
        {
            "head" => Owner() with { Head = new('b', 40) },
            "dirty" => Owner() with { Clean = false },
            "context" => Owner() with { ContextSha256 = new('b', 64) },
            _ => Owner() with { SnapshotSha256 = new('b', 64) },
        };
        _ = Assert.Throws<MigrationExecutionException>(() => ApprovedCurrentCustomerSequenceDefinition.Create(Source(), owner, new('a', 40), Source().CatalogReportSha256, Now));
    }

    [Fact]
    public void Reviewed_owner_revision_requires_current_head_even_when_model_bytes_are_unchanged()
    {
        const string current = "f845b030dc74a179fe0f5021183828fa045775bc";
        const string previous = "e8493c35ca02e1ad0b35acf17d57c64640d263d8";
        Assert.Equal(current, ApprovedCurrentCustomerSequenceDefinition.CustomerOwnerHead);
        _ = ApprovedCurrentCustomerSequenceDefinition.Create(Source(), Owner() with { Head = current },
            new('a', 40), Source().CatalogReportSha256, Now);
        _ = Assert.Throws<MigrationExecutionException>(() => ApprovedCurrentCustomerSequenceDefinition.Create(
            Source(), Owner() with { Head = previous }, new('a', 40), Source().CatalogReportSha256, Now));
    }

    [Theory]
    [InlineData(999L)]
    [InlineData(69832L)]
    [InlineData(2147483647L)]
    public void Fresh_current_report_and_allocation_do_not_require_replaying_historical_capture(long current)
    {
        CurrentCustomerSequenceSource source = Source() with { CatalogReportSha256 = new('b', 64), CurrentValue = current };
        ApprovedCurrentCustomerSequenceDefinition contract = ApprovedCurrentCustomerSequenceDefinition.Create(
            source, Owner(), source.CommitSha, source.CatalogReportSha256, Now);
        Assert.NotEqual(Contract().ComputeSha256(), contract.ComputeSha256());
        ApprovedCurrentCustomerSequenceDefinition.RequirePreserved(Observation(State()), Observation(Final(State())), "legacy_local");
    }

    [Theory]
    [InlineData(998L)]
    [InlineData(-1L)]
    [InlineData(2147483648L)]
    public void Current_allocation_must_fit_fixed_source_identity_bounds(long current)
    {
        CurrentCustomerSequenceSource source = Source() with { CurrentValue = current };
        _ = Assert.Throws<MigrationExecutionException>(() => ApprovedCurrentCustomerSequenceDefinition.Create(
            source, Owner(), source.CommitSha, source.CatalogReportSha256, Now));
    }

    [Theory]
    [InlineData("mismatch")]
    [InlineData("short")]
    [InlineData("nonhex")]
    public void Independently_supplied_current_report_pin_must_match_and_have_exact_hash_shape(string kind)
    {
        string pin = kind switch { "mismatch" => new('b', 64), "short" => new('c', 63), _ => new('z', 64) };
        _ = Assert.Throws<MigrationExecutionException>(() => ApprovedCurrentCustomerSequenceDefinition.Create(
            Source(), Owner(), Source().CommitSha, pin, Now));
    }

    [Theory]
    [InlineData("name")]
    [InlineData("owner")]
    [InlineData("dependency")]
    [InlineData("dependency_count")]
    [InlineData("column")]
    [InlineData("identity")]
    [InlineData("type")]
    [InlineData("start")]
    [InlineData("increment")]
    [InlineData("minimum")]
    [InlineData("maximum")]
    [InlineData("cache")]
    [InlineData("cycle")]
    public void Unexpected_or_already_completed_preimages_fail(string field)
    {
        CurrentCustomerSequenceState state = field switch
        {
            "name" => State() with { Name = "Other_seq" },
            "owner" => State() with { Owner = "other" },
            "dependency" => State() with { DependencyType = "a" },
            "dependency_count" => State() with { OwnedDependencyCount = 2 },
            "column" => State() with { Column = "Other" },
            "identity" => State() with { Identity = "a" },
            "type" => State() with { SequenceType = "bigint" },
            "start" => State() with { Start = 1000 },
            "increment" => State() with { Increment = 2 },
            "minimum" => State() with { Minimum = 0 },
            "maximum" => State() with { Maximum = long.MaxValue },
            "cache" => State() with { Cache = 2 },
            _ => State() with { Cycle = true },
        };
        _ = Assert.Throws<MigrationExecutionException>(() => ApprovedCurrentCustomerSequenceDefinition.RequireBefore(Observation(state), "legacy_local"));
    }

    [Theory]
    [InlineData("last")]
    [InlineData("called")]
    [InlineData("log")]
    [InlineData("oid")]
    [InlineData("relfilenode_unchanged")]
    [InlineData("relfilenode_zero")]
    [InlineData("class_extra")]
    [InlineData("definition_extra")]
    public void Allocation_identity_or_extra_native_field_changes_fail(string field)
    {
        CurrentCustomerSequenceState before = State(), after = Final(before);
        after = field switch
        {
            "last" => after with { LastValue = 1000 },
            "called" => after with { IsCalled = false },
            "log" => after with { LogCount = 0 },
            "oid" => after with { SequenceOid = 99 },
            "relfilenode_unchanged" => after with { RelFileNode = before.RelFileNode },
            "relfilenode_zero" => after with { RelFileNode = 0 },
            "class_extra" => after with { ClassExceptRelFileNodeSha256 = new('e', 64) },
            _ => after with { DefinitionExceptStartSha256 = new('e', 64) },
        };
        _ = Assert.Throws<MigrationExecutionException>(() => ApprovedCurrentCustomerSequenceDefinition.RequirePreserved(Observation(before), Observation(after), "legacy_local"));
    }

    [Theory]
    [InlineData("catalog")]
    [InlineData("duplicate")]
    [InlineData("order")]
    [InlineData("rows")]
    [InlineData("journal")]
    [InlineData("sequence")]
    public void Outside_catalog_multiplicity_order_rows_journals_and_other_sequences_are_exact(string field)
    {
        CurrentCustomerSequenceObservation before = Observation(State()), after = Observation(Final(State()));
        CurrentAppOwnedDatabaseSnapshot snapshot = after.Snapshot;
        snapshot = field switch
        {
            "catalog" => snapshot with { Catalog = snapshot.Catalog.Append(new("pg_attribute", "extra", new('e', 64), "1259", "88")).ToArray() },
            "duplicate" => snapshot with { Catalog = snapshot.Catalog.Append(snapshot.Catalog[0]).ToArray() },
            "order" => snapshot with { Catalog = snapshot.Catalog.Reverse().ToArray() },
            "rows" => snapshot with { Relations = snapshot.Relations.Select(x => x with { Rows = x.Rows + 1 }).ToArray() },
            "journal" => snapshot with { Relations = snapshot.Relations.Select(x => x.Name == "journal" ? x with { RowSha256 = new('e', 64) } : x).ToArray() },
            _ => snapshot with { Sequences = snapshot.Sequences.Select(x => x with { TupleSha256 = new('e', 64) }).ToArray() },
        };
        _ = Assert.Throws<MigrationExecutionException>(() => ApprovedCurrentCustomerSequenceDefinition.RequirePreserved(before, after with { Snapshot = snapshot }, "legacy_local"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void High_allocated_and_unallocated_values_are_retained_without_forcing_source_current_value(bool called)
    {
        CurrentCustomerSequenceState before = State() with { LastValue = 2000000000, IsCalled = called };
        ApprovedCurrentCustomerSequenceDefinition.RequirePreserved(Observation(before), Observation(Final(before)), "legacy_local");
    }

    [Theory]
    [InlineData(1)]
    [InlineData(9)]
    public void Trusted_actual_ID_ordinal_is_positive_and_remains_exact(int ordinal)
    {
        var state = State() with { AttributeNumber = checked((short)ordinal) };
        ApprovedCurrentCustomerSequenceDefinition.RequirePreserved(Observation(state), Observation(Final(state)), "legacy_local");
        Assert.NotEqual(ApprovedCurrentCustomerSequenceDefinition.NativeStateSha256(state),
            ApprovedCurrentCustomerSequenceDefinition.NativeStateSha256(state with { AttributeNumber = checked((short)(ordinal + 1)) }));
        _ = Assert.Throws<MigrationExecutionException>(() => ApprovedCurrentCustomerSequenceDefinition.RequireBefore(Observation(state with { AttributeNumber = 0 }), "legacy_local"));
        _ = Assert.Throws<MigrationExecutionException>(() => ApprovedCurrentCustomerSequenceDefinition.RequirePreserved(Observation(state),
            Observation(Final(state) with { AttributeNumber = checked((short)(ordinal + 1)) }), "legacy_local"));
    }
    internal static CurrentCustomerSequenceState State()
    {
        return new("Customer", "public", "Customer", "ID", "Customer_ID_seq",
        "legacy_local", 80, 1, 81, 82, "integer", "d", "integer", "i", 1, 1, 1, 1, int.MaxValue, 1, false,
        69831, true, 32, new('a', 64), new('b', 64), new('c', 64), new('d', 64));
    }

    internal static CurrentCustomerSequenceState Final(CurrentCustomerSequenceState state)
    {
        return state with
        { Start = 1000, RelFileNode = 83, DefinitionTupleSha256 = new('e', 64), ClassTupleSha256 = new('f', 64) };
    }

    internal static CurrentCustomerSequenceObservation Observation(CurrentCustomerSequenceState state)
    {
        return new(state,
            new("Customer",
            [new("pg_sequence", state.DefinitionTupleSha256 + "/1", state.DefinitionTupleSha256, "2224", state.SequenceOid.ToString(System.Globalization.CultureInfo.InvariantCulture)),
         new("pg_class", state.SequenceOid.ToString(System.Globalization.CultureInfo.InvariantCulture), state.ClassTupleSha256, "1259", state.SequenceOid.ToString(System.Globalization.CultureInfo.InvariantCulture)),
         new("pg_attribute", "retained1", new('a', 64), "1259", "80"),
         new("pg_depend", "retained2", new('b', 64), "1259", "81")],
            [new("public", "Customer", 2, new('a', 64)), new("private", "journal", 1, new('b', 64))],
            [new("public", "Customer_ID_seq", state.Owner, new('c', 64)), new("private", "Other_seq", state.Owner, new('d', 64))]));
    }
}

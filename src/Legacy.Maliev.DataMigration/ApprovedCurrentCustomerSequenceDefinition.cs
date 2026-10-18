using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

internal sealed record CurrentCustomerSequenceSource(string CommitSha, string CatalogReportSha256,
    DateTimeOffset ObservedAtUtc, long Seed, long Increment, long CurrentValue);

internal sealed record CurrentCustomerSequenceOwner(string Head, bool Clean, DateTimeOffset ObservedAtUtc,
    string ContextSha256, string SnapshotSha256);

internal sealed record CurrentCustomerSequenceState(string Database, string Schema, string Table, string Column,
    string Name, string Owner, uint TableOid, short AttributeNumber, uint SequenceOid, uint RelFileNode,
    string ColumnType, string Identity, string SequenceType, string DependencyType, int OwnedDependencyCount,
    long Start, long Increment, long Minimum, long Maximum, long Cache, bool Cycle,
    long LastValue, bool IsCalled, long LogCount, string DefinitionExceptStartSha256,
    string ClassExceptRelFileNodeSha256, string DefinitionTupleSha256, string ClassTupleSha256);

internal sealed record CurrentCustomerSequenceObservation(CurrentCustomerSequenceState State,
    CurrentAppOwnedDatabaseSnapshot Snapshot);

/// <summary>Pure fixed physical preparation; native semantics require the trusted reader and signed native-state pin.</summary>
internal sealed class ApprovedCurrentCustomerSequenceDefinition
{
    internal const string CustomerOwnerHead = "f845b030dc74a179fe0f5021183828fa045775bc";
    internal const string ContextSha256 = "6e5d93ba8d385099b0d06d782db17344fe9656fc056ddeed1c00c2f07710b970";
    internal const string OwnerSnapshotSha256 = "795475768f136faad32445b7eafa56d87ad6b98a58394292329b4534e450a7be";
    internal const string CandidateSql = "ALTER SEQUENCE public.\"Customer_ID_seq\" START WITH 1000;";
    private readonly string _digest;

    private ApprovedCurrentCustomerSequenceDefinition(CurrentCustomerSequenceSource source, CurrentCustomerSequenceOwner owner)
    {
        byte[] payload = [.. "Legacy.Maliev.CurrentCustomerSequence.DefinitionPreparation.v1\0"u8,
            .. JsonSerializer.SerializeToUtf8Bytes(new
            {
                source.CommitSha, source.CatalogReportSha256, source.Seed, source.Increment, source.CurrentValue,
                owner.Head, owner.ContextSha256, owner.SnapshotSha256,
                Database = "Customer", Sequence = "public.Customer_ID_seq", Column = "public.Customer.ID",
                BeforeStart = 1, AfterStart = 1000,
                NativeReplacement = "same sequence OID pg_class.relfilenode only; preserve all other tuple fields",
            })];
        _digest = Convert.ToHexStringLower(SHA256.HashData(payload));
    }

    internal string ComputeSha256()
    {
        return _digest;
    }

    // This binds bytes of the fully observed native state, including actual ID ordinal and OIDs.
    // The primitive shape checks below cannot decode semantic fields from raw tuple hashes.
    internal static string NativeStateSha256(CurrentCustomerSequenceState state)
    {
        return Convert.ToHexStringLower(SHA256.HashData([.. "Legacy.Maliev.CurrentCustomerSequence.NativeState.v1\0"u8,
            .. JsonSerializer.SerializeToUtf8Bytes(state)]));
    }

    internal static ApprovedCurrentCustomerSequenceDefinition Create(CurrentCustomerSequenceSource source,
        CurrentCustomerSequenceOwner owner, string independentlyAcceptedSourceSha,
        string independentlyAcceptedCurrentReportSha256, DateTimeOffset now)
    {
        return independentlyAcceptedSourceSha.Length != 40 || !independentlyAcceptedSourceSha.All(IsLowerHex) ||
            source.CommitSha != independentlyAcceptedSourceSha || !Hash(independentlyAcceptedCurrentReportSha256) ||
            source.CatalogReportSha256 != independentlyAcceptedCurrentReportSha256 ||
            source.Seed != 1000 || source.Increment != 1 || source.CurrentValue < source.Seed - 1 || source.CurrentValue > int.MaxValue ||
            owner.Head != CustomerOwnerHead || !owner.Clean || owner.ContextSha256 != ContextSha256 ||
            owner.SnapshotSha256 != OwnerSnapshotSha256 || !Fresh(source.ObservedAtUtc, now) || !Fresh(owner.ObservedAtUtc, now)
            ? throw Invalid()
            : new(source, owner);
    }

    internal static void RequireBefore(CurrentCustomerSequenceObservation observation, string independentlyObservedOwner)
    {
        CurrentCustomerSequenceState s = observation.State;
        if (s.Database != "Customer" || observation.Snapshot.Database != "Customer" || s.Schema != "public" ||
            s.Table != "Customer" || s.Column != "ID" || s.Name != "Customer_ID_seq" ||
            string.IsNullOrWhiteSpace(independentlyObservedOwner) || s.Owner != independentlyObservedOwner ||
            s.TableOid == 0 || s.SequenceOid == 0 || s.TableOid == s.SequenceOid || s.RelFileNode == 0 ||
            s.AttributeNumber <= 0 || s.ColumnType != "integer" || s.SequenceType != "integer" ||
            s.Identity != "d" || s.DependencyType != "i" || s.OwnedDependencyCount != 1 ||
            s.Start != 1 || s.Increment != 1 || s.Minimum != 1 || s.Maximum != int.MaxValue ||
            s.Cache != 1 || s.Cycle || s.LastValue < s.Minimum || s.LastValue > s.Maximum || s.LogCount < 0 ||
            !Hash(s.DefinitionExceptStartSha256) || !Hash(s.ClassExceptRelFileNodeSha256) ||
            !Hash(s.DefinitionTupleSha256) || !Hash(s.ClassTupleSha256))
        { throw Invalid(); }
        _ = TargetFacts(observation);
    }

    internal static void RequirePreserved(CurrentCustomerSequenceObservation before, CurrentCustomerSequenceObservation after,
        string independentlyObservedOwner)
    {
        RequireBefore(before, independentlyObservedOwner);
        CurrentCustomerSequenceState old = before.State, current = after.State;
        if (after.Snapshot.Database != "Customer" || current.Start != 1000 || current.RelFileNode == 0 ||
            current.RelFileNode == old.RelFileNode || !Hash(current.DefinitionTupleSha256) || !Hash(current.ClassTupleSha256) ||
            current.DefinitionTupleSha256 == old.DefinitionTupleSha256 || current.ClassTupleSha256 == old.ClassTupleSha256 ||
            current with
            {
                Start = old.Start,
                RelFileNode = old.RelFileNode,
                DefinitionTupleSha256 = old.DefinitionTupleSha256,
                ClassTupleSha256 = old.ClassTupleSha256
            } != old)
        { throw Invalid(); }
        CurrentAppOwnedCatalogFact[] oldFacts = TargetFacts(before), newFacts = TargetFacts(after);
        // Full ordered occurrence-bearing facts remain exact. Only these two bound tuple digests may change.
        for (int index = 0; index < oldFacts.Length; index++)
        {
            CurrentAppOwnedCatalogFact expected = oldFacts[index], observed = newFacts[index];
            string expectedKey = expected.Catalog == "pg_sequence" ? observed.Sha256 + "/1" : expected.Key;
            if (observed with { Sha256 = expected.Sha256, Key = expected.Key } != expected || observed.Key != expectedKey)
            { throw Invalid(); }
        }
        if (!before.Snapshot.Catalog.Where(x => !oldFacts.Contains(x)).SequenceEqual(after.Snapshot.Catalog.Where(x => !newFacts.Contains(x))) ||
            !before.Snapshot.Relations.SequenceEqual(after.Snapshot.Relations) ||
            !before.Snapshot.Sequences.SequenceEqual(after.Snapshot.Sequences))
        { throw Invalid(); }
    }

    private static CurrentAppOwnedCatalogFact[] TargetFacts(CurrentCustomerSequenceObservation observation)
    {
        CurrentCustomerSequenceState s = observation.State;
        string oid = s.SequenceOid.ToString(System.Globalization.CultureInfo.InvariantCulture);
        CurrentAppOwnedCatalogFact[] definition = [.. observation.Snapshot.Catalog.Where(x => x.Catalog == "pg_sequence" && x.ObjectId == oid)];
        CurrentAppOwnedCatalogFact[] relation = [.. observation.Snapshot.Catalog.Where(x => x.Catalog == "pg_class" && x.ObjectId == oid)];
        return definition.Length != 1 || relation.Length != 1 || definition[0].Sha256 != s.DefinitionTupleSha256 ||
            definition[0].Key != s.DefinitionTupleSha256 + "/1" || relation[0].Sha256 != s.ClassTupleSha256 || relation[0].Key != oid ||
            definition[0].ObjectClass.Length == 0 || relation[0].ObjectClass.Length == 0 ||
            observation.Snapshot.Catalog.Distinct().Count() != observation.Snapshot.Catalog.Count ||
            observation.Snapshot.Sequences.Count(x => x.Schema == "public" && x.Name == "Customer_ID_seq" && x.Owner == s.Owner) != 1
            ? throw Invalid()
            : [definition[0], relation[0]];
    }

    private static bool Fresh(DateTimeOffset observed, DateTimeOffset now)
    {
        return observed.Offset == TimeSpan.Zero &&
        now.Offset == TimeSpan.Zero && observed <= now && now - observed <= TimeSpan.FromHours(12);
    }

    private static bool IsLowerHex(char c)
    {
        return c is (>= '0' and <= '9') or (>= 'a' and <= 'f');
    }

    private static bool Hash(string value)
    {
        return value.Length == 64 && value.All(IsLowerHex);
    }

    private static MigrationExecutionException Invalid()
    {
        return new("current_customer_sequence_definition_preparation_invalid",
            "The fixed sequence definition preparation does not establish exact preservation.");
    }
}

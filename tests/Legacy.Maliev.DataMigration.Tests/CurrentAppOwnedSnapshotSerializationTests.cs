using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(LocalSnapshotIoTestGroup.Name)]
public sealed class CurrentAppOwnedSnapshotSerializationTests
{
    [Fact]
    public void Streaming_hash_matches_exact_old_default_serializer_bytes()
    {
        CurrentAppOwnedDatabaseSnapshot snapshot = Snapshot("Customer");
        Assert.Equal(OldHash(snapshot), snapshot.Sha256);
        Assert.Equal(OldHash(snapshot), CurrentAppOwnedSnapshotSerialization.Sha256(snapshot));
        Assert.Equal(OldHash(new[] { snapshot, Snapshot("postgres") }),
            CurrentAppOwnedSnapshotSerialization.Sha256(new[] { snapshot, Snapshot("postgres") }));
        Assert.Equal(OldHash<object?>(null), CurrentAppOwnedSnapshotSerialization.Sha256<object?>(null));
        var unusual = new { Text = "Thai ไทย <>&\"\n\\\u0000", Values = new[] { long.MinValue, 0L, long.MaxValue }, Optional = (string?)null };
        Assert.Equal(OldHash(unusual), CurrentAppOwnedSnapshotSerialization.Sha256(unusual));
    }

    [Fact]
    public void Every_catalog_field_occurrence_and_order_changes_digest_and_intern_identity()
    {
        CurrentAppOwnedDatabaseSnapshot baseline = Snapshot("Customer");
        CurrentAppOwnedCatalogFact fact = baseline.Catalog[0];
        CurrentAppOwnedCatalogFact[] changes =
        [
            fact with { Catalog = "PG_TYPE" }, fact with { Key = "01" }, fact with { Sha256 = new string('b', 64) },
            fact with { ObjectClass = "1248" }, fact with { ObjectId = "2" },
        ];
        var pool = new CurrentAppOwnedSnapshotInternPool();
        CurrentAppOwnedCatalogFact first = pool.Intern(fact);
        Assert.Same(first, pool.Intern(fact with { }));
        foreach (CurrentAppOwnedCatalogFact changed in changes)
        {
            Assert.NotSame(first, pool.Intern(changed));
            Assert.NotEqual(baseline.Sha256, (baseline with { Catalog = [changed, .. baseline.Catalog.Skip(1)] }).Sha256);
        }
        Assert.NotEqual(baseline.Sha256, (baseline with { Catalog = [.. baseline.Catalog.Reverse()] }).Sha256);
        Assert.NotEqual(baseline.Sha256, (baseline with { Catalog = [.. baseline.Catalog, fact] }).Sha256);
        CurrentAppOwnedRelationFact relation = baseline.Relations[0];
        foreach (CurrentAppOwnedRelationFact changed in new[]
        {
            relation with { Schema = "other" }, relation with { Name = "other" },
            relation with { Rows = 3 }, relation with { RowSha256 = new string('b', 64) },
        })
        {
            Assert.NotSame(pool.Intern(relation), pool.Intern(changed));
            Assert.NotEqual(baseline.Sha256, (baseline with { Relations = [changed] }).Sha256);
        }
        CurrentAppOwnedSequenceFact sequence = baseline.Sequences[0];
        foreach (CurrentAppOwnedSequenceFact changed in new[]
        {
            sequence with { Schema = "other" }, sequence with { Name = "other" },
            sequence with { Owner = "other" }, sequence with { TupleSha256 = new string('b', 64) },
        })
        {
            Assert.NotSame(pool.Intern(sequence), pool.Intern(changed));
            Assert.NotEqual(baseline.Sha256, (baseline with { Sequences = [changed] }).Sha256);
        }
        Assert.NotEqual(baseline.Sha256, (baseline with { Database = "Other" }).Sha256);
        Assert.NotEqual(OldHash(new[] { baseline, Snapshot("postgres") }), OldHash(new[] { Snapshot("postgres"), baseline }));
    }

    [Fact]
    public async Task Streaming_roundtrip_keeps_exact_bytes_multiplicity_and_shared_records_across_databases()
    {
        CurrentAppOwnedDatabaseSnapshot first = Snapshot("Customer");
        CurrentAppOwnedDatabaseSnapshot[] original = [first, Snapshot("postgres"), first];
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(original);
        using var input = new ChunkStream(bytes, 7);
        var pool = new CurrentAppOwnedSnapshotInternPool();
        CurrentAppOwnedDatabaseSnapshot[] decoded = await CurrentAppOwnedSnapshotSerialization.ReadBaselineAsync(input, pool, CancellationToken.None);
        Assert.Equal(bytes, JsonSerializer.SerializeToUtf8Bytes(decoded));
        Assert.Equal(OldHash(original), CurrentAppOwnedSnapshotSerialization.Sha256(decoded));
        Assert.Same(decoded[0].Catalog[0], decoded[0].Catalog[2]);
        Assert.Same(decoded[0].Catalog[0], decoded[1].Catalog[0]);
        Assert.Same(decoded[0].Relations[0], decoded[1].Relations[0]);
        Assert.Same(decoded[0].Sequences[0], decoded[1].Sequences[0]);
        Assert.Equal(15, pool.TotalFactCount);
        Assert.Equal(4, pool.UniqueRecordCount);
        Assert.True(input.CanRead);
        Assert.InRange(input.MaximumRequested, 1, 32 * 1024);
        using var output = new MemoryStream();
        await CurrentAppOwnedSnapshotSerialization.WriteAsync(output, decoded, CancellationToken.None);
        Assert.Equal(bytes, output.ToArray());
        Assert.True(output.CanWrite);
    }

    [Fact]
    public async Task Twenty_four_database_fixture_reuses_complete_records_without_deduping_occurrences()
    {
        var pool = new CurrentAppOwnedSnapshotInternPool();
        CurrentAppOwnedDatabaseSnapshot[] original = [.. Enumerable.Range(0, 24).Select(database => new CurrentAppOwnedDatabaseSnapshot(
            "synthetic-" + database, [.. Enumerable.Range(0, 256).Select(index => new CurrentAppOwnedCatalogFact(
                "pg_type", index.ToString(System.Globalization.CultureInfo.InvariantCulture), new string('a', 64), "1247", "1"))], [], []))];
        CurrentAppOwnedDatabaseSnapshot[] shared = [.. original.Select(pool.Intern)];
        Assert.Equal(256, pool.UniqueRecordCount);
        Assert.Equal(24 * 256, pool.TotalFactCount);
        Assert.Same(shared[0].Catalog[0], shared[23].Catalog[0]);
        Assert.Equal(OldHash(original), CurrentAppOwnedSnapshotSerialization.Sha256(shared));
        using var input = new ChunkStream(JsonSerializer.SerializeToUtf8Bytes(original), 113);
        var decodedPool = new CurrentAppOwnedSnapshotInternPool();
        CurrentAppOwnedDatabaseSnapshot[] decoded = await CurrentAppOwnedSnapshotSerialization.ReadBaselineAsync(input, decodedPool, CancellationToken.None);
        Assert.Equal(256, decodedPool.UniqueRecordCount);
        Assert.Equal(24 * 256, decodedPool.TotalFactCount);
        Assert.Equal(OldHash(original), CurrentAppOwnedSnapshotSerialization.Sha256(decoded));
    }

    [Theory]
    [InlineData("[null]")]
    [InlineData("{}")]
    [InlineData("[]{}")]
    [InlineData("[{\"Database\":\"unfinished\\u00")]
    [InlineData("[{\"Database\":\"a\",\"Catalog\":[],\"Relations\":[],\"Sequences\":[]}")]
    [InlineData("[{\"Database\":\"a\",\"Database\":\"b\",\"Catalog\":[],\"Relations\":[],\"Sequences\":[]}]")]
    [InlineData("[{\"Database\":\"a\",\"Unknown\":[],\"Catalog\":[],\"Relations\":[],\"Sequences\":[]}]")]
    [InlineData("[{\"Database\":\"a\",\"Catalog\":null,\"Relations\":[],\"Sequences\":[]}]")]
    [InlineData("[{\"Database\":\"a\",\"Catalog\":[],\"Relations\":[]}]")]
    [InlineData("[{\"Database\":\"a\",\"Catalog\":[null],\"Relations\":[],\"Sequences\":[]}]")]
    public async Task Rejects_null_unknown_duplicate_missing_and_trailing_content(string json)
    {
        using var input = new ChunkStream(Encoding.UTF8.GetBytes(json), 1);
        _ = await Assert.ThrowsAsync<JsonException>(() => CurrentAppOwnedSnapshotSerialization.ReadBaselineAsync(input,
            new CurrentAppOwnedSnapshotInternPool(), CancellationToken.None));
        Assert.True(input.CanRead);
    }

    [Fact]
    public async Task Mid_read_cancellation_returns_no_partial_baseline_and_preserves_caller_stream()
    {
        using var cancellation = new CancellationTokenSource();
        using var input = new ChunkStream(JsonSerializer.SerializeToUtf8Bytes(new[] { Snapshot("Customer") }), 7, cancellation);
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => CurrentAppOwnedSnapshotSerialization.ReadBaselineAsync(input,
            new CurrentAppOwnedSnapshotInternPool(), cancellation.Token));
        Assert.True(input.CanRead);
    }

    [Fact]
    public async Task Rejects_changed_fact_properties_and_all_resource_limit_overflows_without_partial_result()
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(new[] { Snapshot("Customer"), Snapshot("postgres") });
        foreach (CurrentAppOwnedSnapshotLimits limits in new[]
        {
            new CurrentAppOwnedSnapshotLimits(MaximumJsonBytes: bytes.Length - 1),
            new CurrentAppOwnedSnapshotLimits(MaximumDatabases: 1),
            new CurrentAppOwnedSnapshotLimits(MaximumFacts: 1),
            new CurrentAppOwnedSnapshotLimits(MaximumUniqueRecords: 1),
            new CurrentAppOwnedSnapshotLimits(MaximumStringUtf8Bytes: 3),
            new CurrentAppOwnedSnapshotLimits(MaximumUniqueStringCharacters: 1),
        })
        {
            using var input = new ChunkStream(bytes, 29);
            _ = await Assert.ThrowsAsync<JsonException>(() => CurrentAppOwnedSnapshotSerialization.ReadBaselineAsync(input,
                new CurrentAppOwnedSnapshotInternPool(limits), CancellationToken.None));
        }
        string json = Encoding.UTF8.GetString(bytes);
        foreach (string changed in new[]
        {
            json.Replace("\"Catalog\":\"pg_type\"", "\"Catalog\":\"pg_type\",\"Catalog\":\"other\"", StringComparison.Ordinal),
            json.Replace("\"ObjectId\":\"1\"", "\"Unknown\":\"1\"", StringComparison.Ordinal),
            json.Replace("\"Rows\":2", "\"Rows\":9223372036854775808", StringComparison.Ordinal),
            json.Replace("\"Database\":\"Customer\"", "\"Database\":\"" + new string('x', 40_000) + "\"", StringComparison.Ordinal),
        })
        {
            using var input = new ChunkStream(Encoding.UTF8.GetBytes(changed), 503);
            _ = await Assert.ThrowsAsync<JsonException>(() => CurrentAppOwnedSnapshotSerialization.ReadBaselineAsync(input,
                new CurrentAppOwnedSnapshotInternPool(), CancellationToken.None));
        }
    }

    [Fact]
    public void Resource_caps_can_be_tightened_but_not_widened_or_disabled()
    {
        foreach (CurrentAppOwnedSnapshotLimits limits in new[]
        {
            new CurrentAppOwnedSnapshotLimits(MaximumJsonBytes: 0),
            new CurrentAppOwnedSnapshotLimits(MaximumJsonBytes: long.MaxValue),
            new CurrentAppOwnedSnapshotLimits(MaximumDatabases: 257),
            new CurrentAppOwnedSnapshotLimits(MaximumFacts: 4_000_001),
            new CurrentAppOwnedSnapshotLimits(MaximumUniqueRecords: 200_001),
            new CurrentAppOwnedSnapshotLimits(MaximumStringUtf8Bytes: 4097),
            new CurrentAppOwnedSnapshotLimits(MaximumUniqueStringCharacters: 32L * 1024 * 1024 + 1),
        })
        {
            _ = Assert.Throws<ArgumentOutOfRangeException>(() => new CurrentAppOwnedSnapshotInternPool(limits));
        }
    }

    [Fact]
    public async Task Streaming_writer_rejects_before_exceeding_cap_and_preserves_caller_output()
    {
        using var output = new MemoryStream();
        _ = await Assert.ThrowsAsync<JsonException>(() => CurrentAppOwnedSnapshotSerialization.WriteAsync(
            output, new[] { Snapshot("Customer") }, CancellationToken.None, maximumBytes: 13));
        Assert.InRange(output.Length, 0, 13);
        Assert.True(output.CanWrite);
        output.WriteByte(1);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => CurrentAppOwnedSnapshotSerialization.WriteAsync(
            output, new[] { Snapshot("Customer") }, cancellation.Token));
        Assert.True(output.CanWrite);
    }

    [Fact]
    public async Task Cancellation_does_not_close_caller_handle_or_return_partial_baseline()
    {
        using var input = new ChunkStream(JsonSerializer.SerializeToUtf8Bytes(new[] { Snapshot("Customer") }), 1);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => CurrentAppOwnedSnapshotSerialization.ReadBaselineAsync(input,
            new CurrentAppOwnedSnapshotInternPool(), cancellation.Token));
        Assert.True(input.CanRead);
    }

    [Fact]
    public async Task Canonically_escaped_maximum_string_fits_fixed_buffer_and_one_byte_overflow_fails()
    {
        CurrentAppOwnedDatabaseSnapshot snapshot = Snapshot(new string('<', 4096));
        using var input = new ChunkStream(JsonSerializer.SerializeToUtf8Bytes(new[] { snapshot }), 13);
        CurrentAppOwnedDatabaseSnapshot[] decoded = await CurrentAppOwnedSnapshotSerialization.ReadBaselineAsync(input,
            new CurrentAppOwnedSnapshotInternPool(), CancellationToken.None);
        Assert.Equal(snapshot.Sha256, Assert.Single(decoded).Sha256);
        using var oversized = new ChunkStream(JsonSerializer.SerializeToUtf8Bytes(new[] { snapshot with { Database = new string('<', 4097) } }), 13);
        _ = await Assert.ThrowsAsync<JsonException>(() => CurrentAppOwnedSnapshotSerialization.ReadBaselineAsync(oversized,
            new CurrentAppOwnedSnapshotInternPool(), CancellationToken.None));
    }

    [WindowsLocalRunFact]
    public async Task Guarded_baseline_read_retains_owner_handle_and_releases_failed_parse()
    {
        string parent = Path.Combine(Path.GetTempPath(), "snapshot-custody-" + Guid.NewGuid().ToString("N"));
        string root = Path.Combine(parent, "artifacts");
        try
        {
            using WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireFresh(root);
            string path = Path.Combine(root, "global-before.json");
            using (var custody = new CurrentAppOwnedRepairCustody(authority))
            {
                CurrentAppOwnedDatabaseSnapshot[] baseline = [Snapshot("Customer")];
                await custody.WriteBaselineNewAsync(path, baseline, CancellationToken.None);
                Assert.Equal(JsonSerializer.SerializeToUtf8Bytes(baseline), File.ReadAllBytes(path));
                _ = await Assert.ThrowsAsync<IOException>(() => custody.WriteBaselineNewAsync(path, baseline, CancellationToken.None));
                _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => custody.WriteBaselineNewAsync(
                    Path.Combine(parent, "outside.json"), baseline, CancellationToken.None));
                _ = Assert.Single(await custody.ReadBaselineAsync(path, CancellationToken.None));
                _ = Assert.Throws<IOException>(() => File.WriteAllText(path, "changed"));
                custody.Require();
                _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => custody.ReadBaselineAsync(
                    Path.Combine(parent, "outside.json"), CancellationToken.None));
            }
            File.WriteAllText(path, "invalid");
            using (var custody = new CurrentAppOwnedRepairCustody(authority))
            {
                _ = await Assert.ThrowsAsync<JsonException>(() => custody.ReadBaselineAsync(path, CancellationToken.None));
                File.WriteAllText(path, "released");
                custody.Require();
            }
        }
        finally
        {
            if (Directory.Exists(parent)) { Directory.Delete(parent, recursive: true); }
        }
    }

    private static CurrentAppOwnedDatabaseSnapshot Snapshot(string database)
    {
        var fact = new CurrentAppOwnedCatalogFact("pg_type", "1", new string('a', 64), "1247", "1");
        return new(database, [fact, fact with { Key = "2" }, fact with { }],
            [new("public", "synthetic ไทย <>&", 2, new string('a', 64))],
            [new("public", "synthetic_sequence", "owner", new string('a', 64))]);
    }

    private static string OldHash<T>(T value) => Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(value)));

    private sealed class ChunkStream(byte[] bytes, int chunk, CancellationTokenSource? cancelAfterRead = null) : MemoryStream(bytes, writable: false)
    {
        internal int MaximumRequested { get; private set; }
        public override bool CanSeek => false;
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override long Seek(long offset, SeekOrigin loc) => throw new NotSupportedException();
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            MaximumRequested = Math.Max(MaximumRequested, buffer.Length);
            ValueTask<int> result = base.ReadAsync(buffer[..Math.Min(buffer.Length, chunk)], cancellationToken);
            cancelAfterRead?.Cancel();
            return result;
        }
    }
}

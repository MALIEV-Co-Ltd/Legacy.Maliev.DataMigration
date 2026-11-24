using System.Data;
using System.Security.Cryptography;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;
using Npgsql;
using Xunit.Abstractions;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveNativeSizeFactAttribute : FactAttribute
{
    internal const string ParentVariable = "MALIEV_AUTH_ARCHIVE_NATIVE_SIZE_PARENT";
    public CurrentAuthArchiveNativeSizeFactAttribute()
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(ParentVariable)))
        { Skip = "Requires an explicitly admitted protected native-measurement parent. No source credentials or archive proof are produced."; }
    }
}

public sealed class CurrentAuthArchiveNativeSizeTests(ITestOutputHelper output)
{
    [CurrentAuthArchiveNativeSizeFact]
    public async Task Fixed_18_4_catalog_serialization_reports_actual_bytes_for_26_and_49_database_cohorts()
    {
        if (!OperatingSystem.IsWindows()) { throw new PlatformNotSupportedException(); }
        if (Environment.GetEnvironmentVariable("TESTCONTAINERS_RYUK_DISABLED") != "true")
        { throw new InvalidOperationException("Native measurement requires the existing process-only Ryuk-disabled context; it starts no optional cleanup helper."); }
        string parent = Environment.GetEnvironmentVariable(CurrentAuthArchiveNativeSizeFactAttribute.ParentVariable) ?? throw new InvalidOperationException();
        SecureLocalFile.EnsureOwnerOnlyDirectory(parent); CurrentAuthRepairCapacity.Require(admission: true);
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(4));
        CurrentAuthArchiveNativeSizeFixture? fixture = null; Exception? failure = null;
        try
        {
            fixture = await CurrentAuthArchiveNativeSizeFixture.CreateAsync(parent, deadline.Token);
            await CreateCohortAsync("local", 26); await CreateCohortAsync("comparison", 49);
            var sharing = new CurrentAppOwnedSnapshotInternPool();
            var local = await MeasureAsync("local", 26, sharing); var comparison = await MeasureAsync("comparison", 49, sharing);
            long occurrences = local.Facts + comparison.Facts;
            for (int round = 1; round < 3; round++)
            {
                var localAgain = await MeasureAsync("local", 26, sharing);
                var comparisonAgain = await MeasureAsync("comparison", 49, sharing);
                Assert.Equal(local, localAgain); Assert.Equal(comparison, comparisonAgain);
                occurrences = checked(occurrences + localAgain.Facts + comparisonAgain.Facts);
            }
            // These cohorts measure serializer footprint. They are not the Auth paired inventory or proof fixture.
            output.WriteLine(JsonSerializer.Serialize(new
            {
                MeasurementOnly = true,
                SqlSourceQueries = 0,
                ServerVersionNumber = 180004,
                LocalDatabases = 26,
                LocalUtf8Bytes = local.Bytes,
                LocalCatalogFacts = local.Facts,
                ComparisonDatabases = 49,
                ComparisonUtf8Bytes = comparison.Bytes,
                ComparisonCatalogFacts = comparison.Facts,
                CompleteCohorts = 6,
                FactOccurrences = occurrences,
                sharing.UniqueRecordCount,
                sharing.UniqueStringCharacterCount,
                RepeatedSerializedSha256Equal = true
            }));
            Assert.True(local.Bytes > 0); Assert.True(comparison.Bytes > local.Bytes); Assert.True(local.Facts > 0);
            Assert.True(occurrences > sharing.Limits.MaximumFacts);
        }
        catch (Exception primary) { failure = primary; }
        Exception? cleanupFailure = null;
        try { if (fixture is not null) { await fixture.DisposeAsync(); } } catch (Exception cleanup) { cleanupFailure = cleanup; }
        if (cleanupFailure is not null) { throw new AggregateException("Native measurement cleanup failed.", failure is null ? [cleanupFailure] : [failure, cleanupFailure]); }
        if (failure is not null) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw(); }

        string DatabaseName(string cohort, int index)
        {
            return "auth_size_" + fixture.Operation.ToString("N") + "_" + cohort + "_" + index.ToString("D2", System.Globalization.CultureInfo.InvariantCulture);
        }

        async Task CreateCohortAsync(string cohort, int count)
        {
            for (int index = 0; index < count; index++)
            {
                deadline.Token.ThrowIfCancellationRequested();
                string database = DatabaseName(cohort, index);
                await using var admin = new NpgsqlConnection(fixture.AdminConnection);
                await admin.OpenAsync(deadline.Token);
                await using var create = new NpgsqlCommand("CREATE DATABASE \"" + database + "\" TEMPLATE template0 ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C';", admin) { CommandTimeout = 15 };
                _ = await create.ExecuteNonQueryAsync(deadline.Token);
            }
        }
        async Task<(long Bytes, long Facts, string Sha256)> MeasureAsync(string cohort, int count, CurrentAppOwnedSnapshotInternPool sharing)
        {
            using var counter = new CountingStream(deadline.Token); using var writer = new Utf8JsonWriter(counter);
            var budget = sharing.BeginCohort(Enumerable.Range(0, count).Select(index => DatabaseName(cohort, index)));
            writer.WriteStartArray(); long facts = 0;
            foreach (string database in budget.Databases)
            {
                deadline.Token.ThrowIfCancellationRequested(); CurrentAuthRepairCapacity.Require(admission: false);
                await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(fixture.AdminConnection) { Database = database, Pooling = false, CommandTimeout = 15 }.ConnectionString);
                await connection.OpenAsync(deadline.Token); await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, deadline.Token);
                await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, tx)) { _ = await readOnly.ExecuteNonQueryAsync(deadline.Token); }
                var snapshot = await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, tx, deadline.Token);
                await tx.RollbackAsync(deadline.Token); facts = checked(facts + snapshot.Catalog.Count);
                // Only one database snapshot is serialized at a time; bytes are counted and discarded, never logged or retained as raw catalog values.
                JsonSerializer.Serialize(writer, budget.Intern(snapshot)); await writer.FlushAsync(deadline.Token);
            }
            budget.Complete();
            writer.WriteEndArray(); await writer.FlushAsync(deadline.Token); return (counter.Length, facts, counter.Sha256);
        }
    }

    private sealed class CountingStream(CancellationToken lifetime) : Stream
    {
        private long _bytes;
        private readonly IncrementalHash _hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        internal string Sha256 => Convert.ToHexStringLower(_hash.GetCurrentHash());
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => _bytes;
        public override long Position { get => _bytes; set => throw new NotSupportedException(); }
        public override void Flush()
        {
            lifetime.ThrowIfCancellationRequested();
        }

        public override Task FlushAsync(CancellationToken cancellationToken) { cancellationToken.ThrowIfCancellationRequested(); lifetime.ThrowIfCancellationRequested(); return Task.CompletedTask; }
        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            Add(buffer.AsSpan(offset, count));
        }

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            Add(buffer);
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        { cancellationToken.ThrowIfCancellationRequested(); Add(buffer.Span); return ValueTask.CompletedTask; }
        private void Add(ReadOnlySpan<byte> bytes)
        { lifetime.ThrowIfCancellationRequested(); _bytes = checked(_bytes + bytes.Length); if (_bytes > 512L * 1024 * 1024) { throw new IOException("native_measurement_exceeds_existing_512MiB_bound"); } _hash.AppendData(bytes); }
        protected override void Dispose(bool disposing)
        { try { if (disposing) { _hash.Dispose(); } } finally { base.Dispose(disposing); } }
    }
}

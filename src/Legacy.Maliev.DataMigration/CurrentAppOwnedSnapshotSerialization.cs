using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

/// <summary>Resource limits fail closed; they never truncate a preservation baseline.</summary>
internal sealed record CurrentAppOwnedSnapshotLimits(
    long MaximumJsonBytes = 512L * 1024 * 1024,
    int MaximumDatabases = 256,
    int MaximumFacts = 4_000_000,
    int MaximumUniqueRecords = 200_000,
    int MaximumStringUtf8Bytes = 4096,
    long MaximumUniqueStringCharacters = 32L * 1024 * 1024);

/// <summary>Per-run exact immutable record sharing. Each original occurrence remains in its original position.</summary>
internal sealed class CurrentAppOwnedSnapshotInternPool
{
    private readonly Dictionary<CurrentAppOwnedCatalogFact, CurrentAppOwnedCatalogFact> _catalog = [];
    private readonly Dictionary<CurrentAppOwnedRelationFact, CurrentAppOwnedRelationFact> _relations = [];
    private readonly Dictionary<CurrentAppOwnedSequenceFact, CurrentAppOwnedSequenceFact> _sequences = [];
    private int _databases;
    internal CurrentAppOwnedSnapshotLimits Limits { get; }
    internal int TotalFactCount { get; private set; }
    internal int UniqueRecordCount => _catalog.Count + _relations.Count + _sequences.Count;
    internal long UniqueStringCharacterCount { get; private set; }

    internal CurrentAppOwnedSnapshotInternPool(CurrentAppOwnedSnapshotLimits? limits = null)
    {
        Limits = limits ?? new();
        if (Limits.MaximumJsonBytes is <= 0 or > 512L * 1024 * 1024 || Limits.MaximumDatabases is <= 0 or > 256 ||
            Limits.MaximumFacts is <= 0 or > 4_000_000 || Limits.MaximumUniqueRecords is <= 0 or > 200_000 ||
            Limits.MaximumStringUtf8Bytes is <= 0 or > 4096 || Limits.MaximumUniqueStringCharacters is <= 0 or > 32L * 1024 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(limits));
        }
    }

    internal CurrentAppOwnedDatabaseSnapshot Intern(CurrentAppOwnedDatabaseSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        AddDatabase();
        RequireString(snapshot.Database);
        return new(snapshot.Database,
            [.. snapshot.Catalog.Select(Intern)],
            [.. snapshot.Relations.Select(Intern)],
            [.. snapshot.Sequences.Select(Intern)]);
    }

    internal CurrentAppOwnedCatalogFact Intern(CurrentAppOwnedCatalogFact fact)
    {
        RequireString(fact.Catalog); RequireString(fact.Key); RequireString(fact.Sha256);
        RequireString(fact.ObjectClass); RequireString(fact.ObjectId);
        return InternExact(fact, _catalog, (long)fact.Catalog.Length + fact.Key.Length + fact.Sha256.Length + fact.ObjectClass.Length + fact.ObjectId.Length);
    }

    internal CurrentAppOwnedRelationFact Intern(CurrentAppOwnedRelationFact fact)
    {
        RequireString(fact.Schema); RequireString(fact.Name); RequireString(fact.RowSha256);
        return InternExact(fact, _relations, (long)fact.Schema.Length + fact.Name.Length + fact.RowSha256.Length);
    }

    internal CurrentAppOwnedSequenceFact Intern(CurrentAppOwnedSequenceFact fact)
    {
        RequireString(fact.Schema); RequireString(fact.Name); RequireString(fact.Owner); RequireString(fact.TupleSha256);
        return InternExact(fact, _sequences, (long)fact.Schema.Length + fact.Name.Length + fact.Owner.Length + fact.TupleSha256.Length);
    }

    internal void AddDatabase()
    {
        if (_databases >= Limits.MaximumDatabases) { throw new JsonException("Snapshot database limit exceeded."); }
        _databases++;
    }

    private T InternExact<T>(T fact, Dictionary<T, T> records, long stringCharacters) where T : notnull
    {
        if (TotalFactCount >= Limits.MaximumFacts) { throw new JsonException("Snapshot fact limit exceeded."); }
        TotalFactCount++;
        if (records.TryGetValue(fact, out T? existing)) { return existing; }
        if (UniqueRecordCount >= Limits.MaximumUniqueRecords) { throw new JsonException("Snapshot unique record limit exceeded."); }
        if (stringCharacters > Limits.MaximumUniqueStringCharacters - UniqueStringCharacterCount)
        { throw new JsonException("Snapshot retained string limit exceeded."); }
        records.Add(fact, fact);
        UniqueStringCharacterCount += stringCharacters;
        return fact;
    }

    private void RequireString(string value)
    {
        if (value is null || System.Text.Encoding.UTF8.GetByteCount(value) > Limits.MaximumStringUtf8Bytes)
        {
            throw new JsonException("Snapshot string limit exceeded.");
        }
    }
}

/// <summary>Exact default System.Text.Json byte hashing and bounded stream baseline decoding; no file or authority access.</summary>
internal static class CurrentAppOwnedSnapshotSerialization
{
    internal static string Sha256<T>(T value)
    {
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var stream = new HashStream(digest);
        JsonSerializer.Serialize(stream, value);
        return Convert.ToHexStringLower(digest.GetHashAndReset());
    }

    // The caller supplies its already-open, owner-held output handle and owns flushing/custody/readback verification.
    internal static async Task WriteAsync<T>(Stream output, T value, CancellationToken cancellationToken,
        long maximumBytes = 512L * 1024 * 1024)
    {
        ArgumentNullException.ThrowIfNull(output);
        if (maximumBytes is <= 0 or > 512L * 1024 * 1024) { throw new ArgumentOutOfRangeException(nameof(maximumBytes)); }
        using var bounded = new BoundedWriteStream(output, maximumBytes);
        await JsonSerializer.SerializeAsync(bounded, value, cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    // The caller owns its already-open custody-checked handle. No path opening or input disposal occurs here.
    internal static async Task<CurrentAppOwnedDatabaseSnapshot[]> ReadBaselineAsync(Stream input,
        CurrentAppOwnedSnapshotInternPool pool, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(pool);
        using var bounded = new BoundedReadStream(input, pool.Limits.MaximumJsonBytes);
        byte[] buffer = new byte[32 * 1024];
        var parser = new BaselineParser(pool);
        var readerState = new JsonReaderState(new JsonReaderOptions { MaxDepth = 16 });
        int buffered = 0;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int count = await bounded.ReadAsync(buffer.AsMemory(buffered), cancellationToken).ConfigureAwait(false);
            buffered += count;
            bool final = count == 0;
            (int consumed, JsonReaderState next) = Parse(buffer.AsSpan(0, buffered), final, readerState, parser);
            readerState = next;
            buffered -= consumed;
            if (buffered > 0) { buffer.AsSpan(consumed, buffered).CopyTo(buffer); }
            if (final) { return parser.Complete(); }
            if (buffered == buffer.Length) { throw new JsonException("Snapshot token buffer limit exceeded."); }
        }
    }

    private static (int Consumed, JsonReaderState State) Parse(ReadOnlySpan<byte> bytes, bool final,
        JsonReaderState state, BaselineParser parser)
    {
        var reader = new Utf8JsonReader(bytes, final, state);
        while (reader.Read()) { parser.Accept(ref reader); }
        return (checked((int)reader.BytesConsumed), reader.CurrentState);
    }

    private enum ParseStage { Start, SnapshotOrEnd, SnapshotProperty, SnapshotValue, FactOrEnd, FactProperty, FactValue, Done }

    private sealed class BaselineParser(CurrentAppOwnedSnapshotInternPool pool)
    {
        private readonly List<CurrentAppOwnedDatabaseSnapshot> _snapshots = [];
        private ParseStage _stage;
        private int _snapshotProperty;
        private int _snapshotSeen;
        private string? _database;
        private List<CurrentAppOwnedCatalogFact>? _catalog;
        private List<CurrentAppOwnedRelationFact>? _relations;
        private List<CurrentAppOwnedSequenceFact>? _sequences;
        private string[] _fields = [];
        private int _factProperty;
        private int _factSeen;
        private long _rows;
        private static readonly string[][] FactNames =
        [
            [],
            ["Catalog", "Key", "Sha256", "ObjectClass", "ObjectId"],
            ["Schema", "Name", "Rows", "RowSha256"],
            ["Schema", "Name", "Owner", "TupleSha256"],
        ];

        internal void Accept(ref Utf8JsonReader reader)
        {
            switch (_stage)
            {
                case ParseStage.Start:
                    Expect(reader.TokenType, JsonTokenType.StartArray);
                    _stage = ParseStage.SnapshotOrEnd;
                    break;
                case ParseStage.SnapshotOrEnd:
                    if (reader.TokenType == JsonTokenType.EndArray) { _stage = ParseStage.Done; break; }
                    Expect(reader.TokenType, JsonTokenType.StartObject);
                    pool.AddDatabase();
                    _snapshotSeen = 0; _database = null; _catalog = null; _relations = null; _sequences = null;
                    _stage = ParseStage.SnapshotProperty;
                    break;
                case ParseStage.SnapshotProperty:
                    if (reader.TokenType == JsonTokenType.EndObject)
                    {
                        if (_snapshotSeen != 15 || _database is null || _catalog is null || _relations is null || _sequences is null)
                        { throw new JsonException("Incomplete snapshot."); }
                        _snapshots.Add(new(_database, _catalog, _relations, _sequences));
                        _stage = ParseStage.SnapshotOrEnd;
                        break;
                    }
                    Expect(reader.TokenType, JsonTokenType.PropertyName);
                    _snapshotProperty = reader.ValueTextEquals("Database") ? 0 : reader.ValueTextEquals("Catalog") ? 1 :
                        reader.ValueTextEquals("Relations") ? 2 : reader.ValueTextEquals("Sequences") ? 3 : -1;
                    if (_snapshotProperty < 0 || (_snapshotSeen & (1 << _snapshotProperty)) != 0) { throw new JsonException(); }
                    _snapshotSeen |= 1 << _snapshotProperty;
                    _stage = ParseStage.SnapshotValue;
                    break;
                case ParseStage.SnapshotValue:
                    if (_snapshotProperty == 0)
                    {
                        _database = ReadString(ref reader);
                        _stage = ParseStage.SnapshotProperty;
                        break;
                    }
                    Expect(reader.TokenType, JsonTokenType.StartArray);
                    if (_snapshotProperty == 1) { _catalog = []; }
                    else if (_snapshotProperty == 2) { _relations = []; }
                    else { _sequences = []; }
                    _stage = ParseStage.FactOrEnd;
                    break;
                case ParseStage.FactOrEnd:
                    if (reader.TokenType == JsonTokenType.EndArray) { _stage = ParseStage.SnapshotProperty; break; }
                    Expect(reader.TokenType, JsonTokenType.StartObject);
                    _fields = new string[FactNames[_snapshotProperty].Length];
                    _factSeen = 0; _rows = 0;
                    _stage = ParseStage.FactProperty;
                    break;
                case ParseStage.FactProperty:
                    if (reader.TokenType == JsonTokenType.EndObject)
                    {
                        if (_factSeen != (1 << _fields.Length) - 1) { throw new JsonException("Incomplete snapshot fact."); }
                        if (_snapshotProperty == 1) { _catalog!.Add(pool.Intern(new CurrentAppOwnedCatalogFact(_fields[0], _fields[1], _fields[2], _fields[3], _fields[4]))); }
                        else if (_snapshotProperty == 2) { _relations!.Add(pool.Intern(new CurrentAppOwnedRelationFact(_fields[0], _fields[1], _rows, _fields[3]))); }
                        else { _sequences!.Add(pool.Intern(new CurrentAppOwnedSequenceFact(_fields[0], _fields[1], _fields[2], _fields[3]))); }
                        _stage = ParseStage.FactOrEnd;
                        break;
                    }
                    Expect(reader.TokenType, JsonTokenType.PropertyName);
                    _factProperty = -1;
                    for (int index = 0; index < FactNames[_snapshotProperty].Length; index++)
                    {
                        if (reader.ValueTextEquals(FactNames[_snapshotProperty][index])) { _factProperty = index; break; }
                    }
                    if (_factProperty < 0 || (_factSeen & (1 << _factProperty)) != 0) { throw new JsonException(); }
                    _factSeen |= 1 << _factProperty;
                    _stage = ParseStage.FactValue;
                    break;
                case ParseStage.FactValue:
                    if (_snapshotProperty == 2 && _factProperty == 2)
                    {
                        Expect(reader.TokenType, JsonTokenType.Number);
                        if (!reader.TryGetInt64(out _rows)) { throw new JsonException(); }
                    }
                    else { _fields[_factProperty] = ReadString(ref reader); }
                    _stage = ParseStage.FactProperty;
                    break;
                default: throw new JsonException("Trailing snapshot content is not permitted.");
            }
        }

        internal CurrentAppOwnedDatabaseSnapshot[] Complete() =>
            _stage == ParseStage.Done ? [.. _snapshots] : throw new JsonException("Incomplete baseline.");

        private string ReadString(ref Utf8JsonReader reader)
        {
            Expect(reader.TokenType, JsonTokenType.String);
            // Canonical escaping can use six JSON bytes per original UTF8 byte; allocation is bounded before GetString.
            if ((reader.HasValueSequence ? reader.ValueSequence.Length : reader.ValueSpan.Length) > pool.Limits.MaximumStringUtf8Bytes * 6L)
            { throw new JsonException("Snapshot string token limit exceeded."); }
            string value = reader.GetString() ?? throw new JsonException();
            if (System.Text.Encoding.UTF8.GetByteCount(value) > pool.Limits.MaximumStringUtf8Bytes)
            { throw new JsonException("Snapshot string limit exceeded."); }
            return value;
        }

        private static void Expect(JsonTokenType actual, JsonTokenType expected)
        {
            if (actual != expected) { throw new JsonException("Unexpected baseline token."); }
        }
    }
    private sealed class HashStream(IncrementalHash digest) : Stream
    {
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override void Write(byte[] buffer, int offset, int count) => digest.AppendData(buffer, offset, count);
        public override void Write(ReadOnlySpan<byte> buffer) => digest.AppendData(buffer);
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }

    private sealed class BoundedWriteStream(Stream output, long maximumBytes) : Stream
    {
        private long _written;
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => output.CanWrite;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => output.Flush();
        public override Task FlushAsync(CancellationToken cancellationToken) => output.FlushAsync(cancellationToken);
        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            Reserve(buffer.Length);
            output.Write(buffer);
        }
        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Reserve(buffer.Length);
            await output.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
        }
        private void Reserve(int count)
        {
            if (count > maximumBytes - _written) { throw new JsonException("Snapshot byte limit exceeded."); }
            _written += count;
        }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }

    private sealed class BoundedReadStream(Stream input, long maximumBytes) : Stream
    {
        private long _read;
        public override bool CanRead => input.CanRead;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
        public override int Read(Span<byte> buffer)
        {
            int count = input.Read(buffer[..Allowed(buffer.Length)]);
            Add(count);
            return count;
        }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            int count = await input.ReadAsync(buffer[..Allowed(buffer.Length)], cancellationToken).ConfigureAwait(false);
            Add(count);
            return count;
        }
        private int Allowed(int requested) => (int)Math.Min(requested, Math.Min(int.MaxValue, maximumBytes - _read + 1));
        private void Add(int count)
        {
            _read += count;
            if (_read > maximumBytes) { throw new JsonException("Snapshot byte limit exceeded."); }
        }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}


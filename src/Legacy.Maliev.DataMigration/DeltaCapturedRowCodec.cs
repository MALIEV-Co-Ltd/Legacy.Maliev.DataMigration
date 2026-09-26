using System.Buffers.Binary;
using System.IO.Pipelines;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace Legacy.Maliev.DataMigration;

/// <summary>
/// Bounded, schema-bound row serialization for an encrypted live-source capture.
/// A caller must bind the encrypted artifact digest to a signed delta plan before replay.
/// </summary>
public static class DeltaCapturedRowCodec
{
    private static ReadOnlySpan<byte> Magic => "MLVDLT01"u8;
    private const int MaximumHeaderBytes = 4 * 1024 * 1024;
    private const int PipePauseBytes = 2 * 1024 * 1024;

    public static async Task<SnapshotEncryptionResult> EncryptAsync(
        TableCopyPlan table,
        IAsyncEnumerable<MigrationRow> rows,
        Stream encrypted,
        ReadOnlyMemory<byte> rootKey,
        SnapshotArchiveContext context,
        CancellationToken cancellationToken)
    {
        var pipe = new Pipe(new PipeOptions(pauseWriterThreshold: PipePauseBytes,
            resumeWriterThreshold: PipePauseBytes / 2, useSynchronizationContext: false));
        Task producer = WritePipeAsync();
        try
        {
            await using Stream input = pipe.Reader.AsStream(leaveOpen: false);
            SnapshotEncryptionResult result = await SnapshotEncryption.EncryptAsync(
                input, encrypted, rootKey, context, cancellationToken).ConfigureAwait(false);
            await producer.ConfigureAwait(false);
            return result;
        }
        catch
        {
            await pipe.Reader.CompleteAsync().ConfigureAwait(false);
            try { await producer.ConfigureAwait(false); } catch { }
            throw;
        }

        async Task WritePipeAsync()
        {
            await using Stream output = pipe.Writer.AsStream(leaveOpen: false);
            await WriteAsync(table, rows, output, cancellationToken).ConfigureAwait(false);
        }
    }

    public static async IAsyncEnumerable<MigrationRow> DecryptAsync(
        TableCopyPlan table,
        Stream encrypted,
        ReadOnlyMemory<byte> rootKey,
        SnapshotArchiveContext context,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var pipe = new Pipe(new PipeOptions(pauseWriterThreshold: PipePauseBytes,
            resumeWriterThreshold: PipePauseBytes / 2, useSynchronizationContext: false));
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        Task decrypt = DecryptPipeAsync();
        try
        {
            await using Stream input = pipe.Reader.AsStream(leaveOpen: false);
            await foreach (MigrationRow row in ReadAsync(table, input, linked.Token)
                .WithCancellation(linked.Token).ConfigureAwait(false))
            {
                yield return row;
            }
            await decrypt.ConfigureAwait(false);
        }
        finally
        {
            await linked.CancelAsync().ConfigureAwait(false);
            await pipe.Reader.CompleteAsync().ConfigureAwait(false);
            try { await decrypt.ConfigureAwait(false); }
            catch (OperationCanceledException) when (linked.IsCancellationRequested) { }
        }

        async Task DecryptPipeAsync()
        {
            await using Stream output = pipe.Writer.AsStream(leaveOpen: false);
            await SnapshotEncryption.DecryptAsync(encrypted, output, rootKey, context, linked.Token)
                .ConfigureAwait(false);
        }
    }

    internal static async Task WriteAsync(TableCopyPlan table, IAsyncEnumerable<MigrationRow> rows,
        Stream destination, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(rows);
        ArgumentNullException.ThrowIfNull(destination);
        CanonicalDeltaPlanner.ValidateTable(table);
        await destination.WriteAsync(Magic.ToArray(), cancellationToken).ConfigureAwait(false);
        await WriteLengthPrefixedAsync(destination, Encoding.UTF8.GetBytes(
            $"{table.SourceSchema}.{table.SourceTable}|{table.TargetSchema}.{table.TargetTable}"), cancellationToken)
            .ConfigureAwait(false);
        await destination.WriteAsync(ComputeTableShapeSha256(table), cancellationToken).ConfigureAwait(false);

        MigrationRow? previous = null;
        await foreach (MigrationRow row in rows.WithCancellation(cancellationToken).ConfigureAwait(false))
        {
            CanonicalDeltaPlanner.ValidateRow(table, row, "capture");
            if (previous is not null && CanonicalDeltaPlanner.CompareKeys(table, previous, row) >= 0)
            {
                throw new DeltaPlanningException("delta_capture_key_order_invalid",
                    "Captured source rows must have distinct ascending primary keys.");
            }

            using var header = new MemoryStream();
            using (var writer = new BinaryWriter(header, Encoding.UTF8, leaveOpen: true))
            {
                writer.Write(table.OrderedColumns.Count);
                foreach (string column in table.OrderedColumns)
                {
                    WriteValueHeader(writer, row.Values[column]);
                    if (header.Length > MaximumHeaderBytes)
                    {
                        throw new DeltaPlanningException("delta_capture_header_too_large",
                            "A captured row exceeds the bounded scalar header size.");
                    }
                }
            }

            byte[] headerBytes = header.ToArray();
            try
            {
                await WriteLengthPrefixedAsync(destination, headerBytes, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(headerBytes);
            }
            foreach (string column in table.OrderedColumns)
            {
                await WriteLobAsync(row.Values[column], destination, cancellationToken).ConfigureAwait(false);
            }
            previous = row;
        }

        await WriteInt32Async(destination, -1, cancellationToken).ConfigureAwait(false);
    }

    internal static async IAsyncEnumerable<MigrationRow> ReadAsync(TableCopyPlan table, Stream source,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(source);
        CanonicalDeltaPlanner.ValidateTable(table);
        byte[] magic = new byte[Magic.Length];
        await source.ReadExactlyAsync(magic, cancellationToken).ConfigureAwait(false);
        if (!magic.AsSpan().SequenceEqual(Magic))
        {
            throw Invalid();
        }
        byte[] name = await ReadLengthPrefixedAsync(source, 1024, cancellationToken).ConfigureAwait(false);
        if (!string.Equals(Encoding.UTF8.GetString(name),
            $"{table.SourceSchema}.{table.SourceTable}|{table.TargetSchema}.{table.TargetTable}",
            StringComparison.Ordinal))
        {
            throw Invalid();
        }
        byte[] observedShape = new byte[32];
        await source.ReadExactlyAsync(observedShape, cancellationToken).ConfigureAwait(false);
        if (!CryptographicOperations.FixedTimeEquals(observedShape, ComputeTableShapeSha256(table)))
        {
            throw Invalid();
        }

        MigrationRow? previous = null;
        while (true)
        {
            int length = await ReadInt32Async(source, cancellationToken).ConfigureAwait(false);
            if (length == -1)
            {
                byte[] trailing = new byte[1];
                if (await source.ReadAsync(trailing, cancellationToken).ConfigureAwait(false) != 0)
                {
                    throw Invalid();
                }
                yield break;
            }
            if (length is < 0 or > MaximumHeaderBytes)
            {
                throw Invalid();
            }

            byte[] header = new byte[length];
            await source.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);
            using var buffer = new MemoryStream(header, writable: false);
            using var reader = new BinaryReader(buffer, Encoding.UTF8, leaveOpen: true);
            if (reader.ReadInt32() != table.OrderedColumns.Count)
            {
                throw Invalid();
            }
            var values = new Dictionary<string, object?>(table.OrderedColumns.Count, StringComparer.Ordinal);
            var lobs = new List<(string Column, StreamingLobKind Kind, long Length)>();
            foreach (string column in table.OrderedColumns)
            {
                (object? value, StreamingLobKind? kind, long lobLength) = ReadValueHeader(reader);
                if (kind is null)
                {
                    values.Add(column, value);
                }
                else
                {
                    lobs.Add((column, kind.Value, lobLength));
                }
            }
            if (buffer.Position != buffer.Length)
            {
                throw Invalid();
            }

            int nextLob = 0;
            for (int index = 0; index < lobs.Count; index++)
            {
                int currentIndex = index;
                (string column, StreamingLobKind kind, long lobLength) = lobs[index];
                values.Add(column, new StreamingLob(kind, lobLength, async (destination, token) =>
                {
                    if (Interlocked.CompareExchange(ref nextLob, currentIndex + 1, currentIndex) != currentIndex)
                    {
                        throw Invalid();
                    }
                    await CopyExactlyAsync(source, destination, lobLength, token).ConfigureAwait(false);
                }));
            }
            var row = new MigrationRow(values);
            CanonicalDeltaPlanner.ValidateRow(table, row, "capture");
            yield return previous is not null && CanonicalDeltaPlanner.CompareKeys(table, previous, row) >= 0 ? throw Invalid() : row;
            if (lobs.Any(item => !((StreamingLob)values[item.Column]!).IsConsumed))
            {
                throw new MigrationExecutionException("delta_capture_lob_not_consumed",
                    "Captured large values must be consumed in column order before advancing.");
            }
            previous = row;
        }
    }

    private static void WriteValueHeader(BinaryWriter writer, object? value)
    {
        switch (value)
        {
            case null or DBNull: writer.Write((byte)0); break;
            case string text: writer.Write((byte)1); WriteString(writer, text); break;
            case byte[] bytes: writer.Write((byte)2); WriteBytes(writer, bytes); break;
            case bool boolean: writer.Write((byte)3); writer.Write(boolean); break;
            case byte unsigned: writer.Write((byte)4); writer.Write(unsigned); break;
            case short small: writer.Write((byte)5); writer.Write(small); break;
            case int integer: writer.Write((byte)6); writer.Write(integer); break;
            case long big: writer.Write((byte)7); writer.Write(big); break;
            case decimal money:
                writer.Write((byte)8);
                foreach (int part in decimal.GetBits(money))
                {
                    writer.Write(part);
                }

                break;
            case float single: writer.Write((byte)9); writer.Write(single); break;
            case double real: writer.Write((byte)10); writer.Write(real); break;
            case DateTime date: writer.Write((byte)11); writer.Write(date.Ticks); writer.Write((byte)date.Kind); break;
            case DateTimeOffset offset: writer.Write((byte)12); writer.Write(offset.Ticks); writer.Write((short)offset.Offset.TotalMinutes); break;
            case Guid guid: writer.Write((byte)13); writer.Write(guid.ToByteArray()); break;
            case TimeSpan time: writer.Write((byte)14); writer.Write(time.Ticks); break;
            case DateOnly dateOnly: writer.Write((byte)15); writer.Write(dateOnly.DayNumber); break;
            case TimeOnly timeOnly: writer.Write((byte)16); writer.Write(timeOnly.Ticks); break;
            case StreamingLob lob when lob.ExpectedByteLength is not null:
                WriteLobHeader(writer, lob.Kind, lob.ExpectedByteLength.Value);
                break;
            case BufferedStreamingLob buffered:
                WriteLobHeader(writer, buffered.Kind, buffered.CanonicalByteLength);
                break;
            case StreamingLob:
                throw new DeltaPlanningException("delta_capture_lob_length_missing",
                    "A captured large value needs an exact length.");
            default:
                throw new DeltaPlanningException("delta_capture_type_unsupported",
                    "A source scalar type cannot be captured losslessly.");
        }
    }

    private static void WriteLobHeader(BinaryWriter writer, StreamingLobKind kind, long length)
    {
        if (!Enum.IsDefined(kind) || length < 0 || length > 1_000_000_000)
        {
            throw new DeltaPlanningException("delta_capture_lob_length_invalid",
                "A captured large value exceeds the bounded supported length.");
        }

        writer.Write((byte)17);
        writer.Write((byte)kind);
        writer.Write(length);
    }

    private static (object? Value, StreamingLobKind? Kind, long Length) ReadValueHeader(BinaryReader reader)
    {
        byte type = reader.ReadByte();
        return type switch
        {
            0 => (null, null, 0),
            1 => (Encoding.UTF8.GetString(ReadBytes(reader)), null, 0),
            2 => (ReadBytes(reader), null, 0),
            3 => (reader.ReadBoolean(), null, 0),
            4 => (reader.ReadByte(), null, 0),
            5 => (reader.ReadInt16(), null, 0),
            6 => (reader.ReadInt32(), null, 0),
            7 => (reader.ReadInt64(), null, 0),
            8 => (new decimal([reader.ReadInt32(), reader.ReadInt32(), reader.ReadInt32(), reader.ReadInt32()]), null, 0),
            9 => (reader.ReadSingle(), null, 0),
            10 => (reader.ReadDouble(), null, 0),
            11 => (new DateTime(reader.ReadInt64(), (DateTimeKind)reader.ReadByte()), null, 0),
            12 => (new DateTimeOffset(reader.ReadInt64(), TimeSpan.FromMinutes(reader.ReadInt16())), null, 0),
            13 => (new Guid(reader.ReadBytes(16)), null, 0),
            14 => (new TimeSpan(reader.ReadInt64()), null, 0),
            15 => (DateOnly.FromDayNumber(reader.ReadInt32()), null, 0),
            16 => (new TimeOnly(reader.ReadInt64()), null, 0),
            17 => ReadLobHeader(reader),
            _ => throw Invalid(),
        };
    }

    private static (object?, StreamingLobKind?, long) ReadLobHeader(BinaryReader reader)
    {
        StreamingLobKind kind = (StreamingLobKind)reader.ReadByte();
        long length = reader.ReadInt64();
        return !Enum.IsDefined(kind) || length < 0 || length > 1_000_000_000 ? throw Invalid() : ((object?, StreamingLobKind?, long))(null, kind, length);
    }

    private static async Task WriteLobAsync(object? value, Stream destination, CancellationToken cancellationToken)
    {
        if (value is StreamingLob lob)
        {
            long expected = lob.ExpectedByteLength ?? throw new DeltaPlanningException(
                "delta_capture_lob_length_missing", "A captured large value needs an exact length.");
            await lob.ConsumeAsync(destination, cancellationToken).ConfigureAwait(false);
            if (lob.CanonicalByteLength != expected)
            {
                throw Invalid();
            }
        }
        else if (value is BufferedStreamingLob buffered)
        {
            await using Stream input = buffered.OpenRead();
            await input.CopyToAsync(destination, 64 * 1024, cancellationToken).ConfigureAwait(false);
        }
    }

    private static void WriteBytes(BinaryWriter writer, byte[] bytes)
    {
        if (bytes.Length > MaximumHeaderBytes)
        {
            throw new DeltaPlanningException("delta_capture_header_too_large",
                "A captured scalar exceeds the bounded header size.");
        }
        writer.Write(bytes.Length);
        writer.Write(bytes);
    }

    private static void WriteString(BinaryWriter writer, string value)
    {
        if (Encoding.UTF8.GetByteCount(value) > MaximumHeaderBytes)
        {
            throw new DeltaPlanningException("delta_capture_header_too_large",
                "A captured scalar exceeds the bounded header size.");
        }
        WriteBytes(writer, Encoding.UTF8.GetBytes(value));
    }

    private static byte[] ComputeTableShapeSha256(TableCopyPlan table)
    {
        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true))
        {
            writer.Write("legacy-maliev-delta-capture-table-v1");
            writer.Write(table.OrderedColumns.Count);
            foreach (string column in table.OrderedColumns)
            {
                writer.Write(column);
                writer.Write(table.SourceColumnTypes.GetValueOrDefault(column, string.Empty));
                writer.Write(table.ColumnTypes.GetValueOrDefault(column, string.Empty));
                writer.Write(table.NullableColumns.Contains(column, StringComparer.Ordinal));
                writer.Write(table.IdentityColumns.Contains(column, StringComparer.Ordinal));
            }
            writer.Write(table.PrimaryKey!.Columns.Count);
            foreach (string column in table.PrimaryKey.Columns)
            {
                writer.Write(column);
            }
        }
        return SHA256.HashData(stream.ToArray());
    }

    private static byte[] ReadBytes(BinaryReader reader)
    {
        int length = reader.ReadInt32();
        return length < 0 || length > MaximumHeaderBytes || length > reader.BaseStream.Length - reader.BaseStream.Position
            ? throw Invalid()
            : reader.ReadBytes(length);
    }

    private static async Task WriteLengthPrefixedAsync(Stream stream, byte[] bytes, CancellationToken cancellationToken)
    {
        await WriteInt32Async(stream, bytes.Length, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<byte[]> ReadLengthPrefixedAsync(Stream stream, int maximum, CancellationToken cancellationToken)
    {
        int length = await ReadInt32Async(stream, cancellationToken).ConfigureAwait(false);
        if (length < 0 || length > maximum)
        {
            throw Invalid();
        }

        byte[] bytes = new byte[length];
        await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
        return bytes;
    }

    private static async Task WriteInt32Async(Stream stream, int value, CancellationToken cancellationToken)
    {
        byte[] bytes = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(bytes, value);
        await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<int> ReadInt32Async(Stream stream, CancellationToken cancellationToken)
    {
        byte[] bytes = new byte[sizeof(int)];
        await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
        return BinaryPrimitives.ReadInt32BigEndian(bytes);
    }

    private static async Task CopyExactlyAsync(Stream source, Stream destination, long length, CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[64 * 1024];
        try
        {
            long remaining = length;
            while (remaining > 0)
            {
                int read = await source.ReadAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, remaining)),
                    cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    throw Invalid();
                }

                await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                remaining -= read;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    private static MigrationExecutionException Invalid()
    {
        return new("delta_capture_invalid", "The captured row stream failed integrity or shape validation.");
    }
}

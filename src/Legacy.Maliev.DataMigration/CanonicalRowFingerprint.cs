using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Legacy.Maliev.DataMigration;

public sealed class CanonicalRowFingerprint : IDisposable
{
    private readonly IncrementalHash _hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

    public void Append(TableCopyPlan table, IEnumerable<MigrationRow> rows)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(rows);
        foreach (MigrationRow row in rows)
        {
            if (row.Values.Count != table.OrderedColumns.Count ||
                table.OrderedColumns.Any(column => !row.Values.ContainsKey(column)))
            {
                throw new InvalidOperationException(
                    "Migration row does not exactly match the approved column shape.");
            }

            _hash.AppendData([0x52]);
            AppendLength(table.OrderedColumns.Count);
            foreach (string column in table.OrderedColumns)
            {
                string type = table.ColumnTypes.GetValueOrDefault(column, string.Empty);
                _hash.AppendData([0x46]);
                AppendLengthPrefixed(Encoding.UTF8.GetBytes(type));
                object? value = row.Values.GetValueOrDefault(column);
                if (value is null or DBNull)
                {
                    _hash.AppendData([0x00]);
                }
                else
                {
                    _hash.AppendData([0x01]);
                    if (value is ReplayableLob lob)
                    {
                        AppendReplayable(lob);
                    }
                    else
                    {
                        AppendLengthPrefixed(Encoding.UTF8.GetBytes(CanonicalValue(value, type)));
                    }
                }
            }

            _hash.AppendData([0x45]);
        }
    }

    public string Finish()
    {
        return Convert.ToHexString(_hash.GetHashAndReset()).ToLowerInvariant();
    }

    public static string Compute(TableCopyPlan table, IEnumerable<MigrationRow> rows)
    {
        using CanonicalRowFingerprint fingerprint = new();
        fingerprint.Append(table, rows);
        return fingerprint.Finish();
    }

    public void Dispose()
    {
        _hash.Dispose();
    }

    private void AppendLengthPrefixed(ReadOnlySpan<byte> value)
    {
        AppendLength(value.Length);
        _hash.AppendData(value);
    }

    private void AppendReplayable(ReplayableLob lob)
    {
        Span<byte> length = stackalloc byte[sizeof(long)];
        BinaryPrimitives.WriteInt64BigEndian(length, lob.ByteLength);
        _hash.AppendData(length);
        using Stream stream = lob.OpenRead();
        byte[] buffer = new byte[64 * 1024];
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) != 0)
        {
            _hash.AppendData(buffer.AsSpan(0, read));
        }
    }

    private void AppendLength(int value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(bytes, value);
        _hash.AppendData(bytes);
    }

    private static string CanonicalValue(object value, string postgresqlType)
    {
        if (string.Equals(postgresqlType, "date", StringComparison.Ordinal))
        {
            return value switch
            {
                DateOnly date => date.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
                DateTime date => date.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
                _ => CanonicalUntypedValue(value),
            };
        }

        if (string.Equals(postgresqlType, "timestamp without time zone", StringComparison.Ordinal))
        {
            return value is DateTime date
                ? TruncateToMicroseconds(date).ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff", CultureInfo.InvariantCulture)
                : CanonicalUntypedValue(value);
        }

        if (string.Equals(postgresqlType, "timestamp with time zone", StringComparison.Ordinal))
        {
            DateTime? utc = value switch
            {
                DateTimeOffset offset => offset.UtcDateTime,
                DateTime date when date.Kind == DateTimeKind.Utc => date,
                DateTime => throw new InvalidOperationException(
                    "A timestamp with time zone value must carry an explicit UTC offset."),
                _ => null,
            };
            return utc is null
                ? CanonicalUntypedValue(value)
                : TruncateToMicroseconds(utc.Value).ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture);
        }

        return CanonicalUntypedValue(value);
    }

    private static DateTime TruncateToMicroseconds(DateTime value)
    {
        return new(value.Ticks - (value.Ticks % TimeSpan.TicksPerMicrosecond), value.Kind);
    }

    private static string CanonicalUntypedValue(object value)
    {
        return value switch
        {
            string text => text,
            byte[] bytes => Convert.ToHexString(bytes).ToLowerInvariant(),
            DateTime dateTime => dateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff", CultureInfo.InvariantCulture),
            DateTimeOffset offset => offset.ToString("O", CultureInfo.InvariantCulture),
            bool boolean => boolean ? "true" : "false",
            IFormattable formattable => formattable.ToString(null, CultureInfo.InvariantCulture) ?? string.Empty,
            _ => value.ToString() ?? string.Empty,
        };
    }
}

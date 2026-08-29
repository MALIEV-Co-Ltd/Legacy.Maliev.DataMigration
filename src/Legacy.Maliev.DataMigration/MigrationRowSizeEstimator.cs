using System.Globalization;
using System.Text;

namespace Legacy.Maliev.DataMigration;

internal static class MigrationRowSizeEstimator
{
    private const int FieldEnvelopeBytes = 16;

    public static long Estimate(MigrationRow row)
    {
        ArgumentNullException.ThrowIfNull(row);
        long total = 0;
        foreach ((string column, object? value) in row.Values)
        {
            total = checked(total + FieldEnvelopeBytes + Encoding.UTF8.GetByteCount(column));
            total = checked(total + ValueBytes(value));
        }

        return total;
    }

    private static long ValueBytes(object? value)
    {
        return value switch
        {
            null or DBNull => 1,
            byte[] bytes => bytes.LongLength,
            StreamingLob => 64,
            string text => Encoding.UTF8.GetByteCount(text),
            bool or byte or sbyte => 1,
            short or ushort or char => 2,
            int or uint or float or DateOnly => 4,
            long or ulong or double or DateTime or DateTimeOffset or TimeOnly => 16,
            decimal or Guid => 16,
            IFormattable formattable => Encoding.UTF8.GetByteCount(
                formattable.ToString(null, CultureInfo.InvariantCulture) ?? string.Empty),
            _ => Encoding.UTF8.GetByteCount(value.ToString() ?? string.Empty),
        };
    }
}

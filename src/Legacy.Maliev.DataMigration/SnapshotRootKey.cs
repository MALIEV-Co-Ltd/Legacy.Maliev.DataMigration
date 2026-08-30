using System.Security.Cryptography;
using System.Text;

namespace Legacy.Maliev.DataMigration;

public static class SnapshotRootKey
{
    public static byte[] Load(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        using FileStream stream = SecureSnapshotFileCreation.OpenValidatedRead(path);
        return Load(stream);
    }

    public static byte[] Load(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanRead || !stream.CanSeek)
        {
            throw new InvalidOperationException("The snapshot root key stream must be readable and seekable.");
        }
        if (stream.Length is <= 0 or > 4096)
        {
            throw new InvalidOperationException("The snapshot root key file has an invalid size.");
        }

        using var reader = new StreamReader(stream, new UTF8Encoding(false, true), false, leaveOpen: true);
        char[] characters = new char[4096];
        byte[] key = new byte[32];
        try
        {
            int count = reader.ReadBlock(characters, 0, characters.Length);
            int start = 0, end = count;
            while (start < end && char.IsWhiteSpace(characters[start]))
            {
                start++;
            }

            while (end > start && char.IsWhiteSpace(characters[end - 1]))
            {
                end--;
            }

            return !Convert.TryFromBase64Chars(characters.AsSpan(start, end - start), key, out int written) || written != 32
                ? throw new InvalidOperationException("The snapshot root key file is invalid.")
                : key;
        }
        catch { CryptographicOperations.ZeroMemory(key); throw; }
        finally { Array.Clear(characters); }
    }
}

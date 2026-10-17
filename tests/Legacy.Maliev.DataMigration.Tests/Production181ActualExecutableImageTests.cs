using System.Security.Cryptography;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class Production181ActualExecutableImageTests
{
    [WindowsLocalRunFact]
    public void Actual_current_public_executing_image_is_held_hashed_and_disposed()
    {
        using var image = Production181ActualExecutableImage.OpenCurrent();
        image.Require(); Assert.Equal(Environment.ProcessId, image.ProcessId);
        Assert.Equal(Environment.ProcessPath, image.Path, StringComparer.OrdinalIgnoreCase);
        using (var independent = new FileStream(image.Path, FileMode.Open, FileAccess.Read, FileShare.Read))
        { Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(independent)), image.Sha256); }
        image.Dispose(); image.Dispose();
        _ = Assert.Throws<ObjectDisposedException>(image.Require);
    }
}

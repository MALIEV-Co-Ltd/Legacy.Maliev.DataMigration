using System.Text;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class LocalDockerFileBatchTests
{
    private const string Host = "npipe:////./pipe/dockerDesktopLinuxEngine";
    private static readonly string[] ReadlinkArguments = ["readlink", "-e", "--zero", "--"];
    private static readonly string[] StatArguments = ["stat", "--printf=%n\\0%d\\0%i\\0%F\\0", "--"];

    [Theory]
    [InlineData(48, 0, 4)]
    [InlineData(33, 0, 4)]
    [InlineData(10, 1100, 8)]
    [InlineData(10, 1100, 10, true)]
    public async Task StatMany_BoundsEveryCommandAndMapsEachIdentityInOrder(int count, int padding, int commandCount, bool unicode = false)
    {
        string[] paths = Enumerable.Range(0, count).Select(index => "/data/p" + new string(unicode ? 'ก' : 'x', padding) + $"/{index}.mdf").ToArray();
        var process = new FakeDockerProcess
        {
            BatchResult = (args, output) => new(0, args.Contains("stat") ?
                string.Concat(Paths(args).Select(path => path + "\0" + "7\0" + (Array.IndexOf(paths, path) + 100) + "\0regular file\0")) : output, "")
        };
        var result = await new LocalDockerResourceObserver(process).StatManyAsync(Host, SourceObservationFixture.ContainerId, paths, CancellationToken.None);
        Assert.Equal(commandCount, process.Commands.Count);
        Assert.Equal(count, result.Length);
        for (int index = 0; index < count; index++) { Assert.Equal(new FileSystemObjectIdentity("7", (index + 100).ToString(System.Globalization.CultureInfo.InvariantCulture), "regular file"), result[index]); }
        foreach (IReadOnlyList<string> command in process.Commands)
        {
            Assert.Equal(["--host", Host, "exec", SourceObservationFixture.ContainerId], command.Take(4));
            Assert.InRange(Paths(command).Length, 1, 32);
            Assert.True(command.Sum(arg => Math.Max((2L * arg.Length) + 3, Encoding.UTF8.GetByteCount(arg) + 1L)) <= 8192);
            Assert.DoesNotContain("sh", command);
            Assert.DoesNotContain("--dereference", command);
        }
        Assert.Equal(paths, process.Commands.Where(command => command.Contains("readlink")).SelectMany(Paths));
        Assert.Equal(paths, process.Commands.Where(command => command.Contains("stat")).SelectMany(Paths));
        for (int index = 0; index < process.Commands.Count; index += 2)
        {
            Assert.Equal(ReadlinkArguments, process.Commands[index].Skip(4).Take(4));
            Assert.Equal(StatArguments, process.Commands[index + 1].Skip(4).Take(3));
            Assert.Equal(Paths(process.Commands[index]), Paths(process.Commands[index + 1]));
        }
    }

    [Fact]
    public async Task StatMany_ShellMetacharactersAndWhitespace_AreLiteralArgumentsAndUntrimmedRecords()
    {
        string[] paths = ["/data/a 'quoted' \"double\" \\backslash $variable;|--.mdf ", "/data/ภาษาไทย.mdf"];
        var process = new FakeDockerProcess();
        var result = await new LocalDockerResourceObserver(process).StatManyAsync(Host, SourceObservationFixture.ContainerId, paths, CancellationToken.None);
        Assert.Equal(2, result.Length);
        Assert.All(process.Commands, command => Assert.Equal(paths, Paths(command)));
    }

    [Theory]
    [InlineData("remote")]
    [InlineData("container")]
    [InlineData("relative")]
    [InlineData("duplicate")]
    [InlineData("parent")]
    [InlineData("double-slash")]
    [InlineData("control")]
    [InlineData("oversized")]
    [InlineData("host-oversized")]
    public async Task StatMany_ValidatesEntireRequestBeforeFirstProcess(string failure)
    {
        string host = Host, container = SourceObservationFixture.ContainerId;
        string[] paths = Enumerable.Range(0, 65).Select(index => $"/data/{index}.mdf").ToArray();
        switch (failure)
        {
            case "remote": host = "tcp://remote:2375"; break;
            case "container": container = "--option"; break;
            case "relative": paths[^1] = "relative"; break;
            case "duplicate": paths[^1] = paths[0]; break;
            case "parent": paths[^1] = "/data/../escape"; break;
            case "double-slash": paths[^1] = "/data//file"; break;
            case "control": paths[^1] = "/data/file\0ignored"; break;
            case "oversized": paths[^1] = "/" + new string('x', 8192); break;
            case "host-oversized": host = "unix:///" + new string('x', 8192); break;
            default: throw new InvalidOperationException();
        }
        var process = new FakeDockerProcess();
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => new LocalDockerResourceObserver(process)
            .StatManyAsync(host, container, paths, CancellationToken.None));
        Assert.Empty(process.Commands);
    }

    [Theory]
    [InlineData("readlink-missing", "filesystem_framing")]
    [InlineData("readlink-extra", "filesystem_framing")]
    [InlineData("readlink-unterminated", "filesystem_framing")]
    [InlineData("readlink-trailing", "filesystem_framing")]
    [InlineData("readlink-reordered", "filesystem_path_alias")]
    [InlineData("readlink-alias", "filesystem_path_alias")]
    [InlineData("stat-missing", "filesystem_framing")]
    [InlineData("stat-extra", "filesystem_framing")]
    [InlineData("stat-unterminated", "filesystem_framing")]
    [InlineData("stat-trailing", "filesystem_framing")]
    [InlineData("stat-reordered", "filesystem_path_alias")]
    [InlineData("stat-alias", "filesystem_path_alias")]
    [InlineData("stat-symlink", "filesystem_identity")]
    [InlineData("stat-directory", "filesystem_identity")]
    [InlineData("stat-zero-device", "filesystem_identity")]
    [InlineData("stat-bad-device", "filesystem_identity")]
    [InlineData("stat-zero-inode", "filesystem_identity")]
    [InlineData("stat-overflow-inode", "filesystem_identity")]
    [InlineData("stat-space-inode", "filesystem_identity")]
    [InlineData("readlink-exit", "docker_process")]
    [InlineData("stat-exit", "docker_process")]
    public async Task StatMany_RejectsIncompleteOrMismatchedRecordsWithoutPartialResult(string failure, string boundary)
    {
        string[] paths = ["/data/a.mdf", "/data/b.mdf"];
        var process = new FakeDockerProcess
        {
            BatchResult = (args, output) =>
            {
                bool readlink = args.Contains("readlink");
                if (readlink != failure.StartsWith("readlink", StringComparison.Ordinal)) { return new(0, output, ""); }
                if (failure.EndsWith("exit", StringComparison.Ordinal)) { return new(1, "do-not-log", "do-not-log"); }
                string[] fields = output.Split('\0');
                string altered = failure switch
                {
                    "readlink-missing" => paths[0] + "\0",
                    "readlink-extra" => output + "/extra\0",
                    "readlink-unterminated" or "stat-unterminated" => output[..^1],
                    "readlink-trailing" or "stat-trailing" => output + " \r\n",
                    "readlink-reordered" => paths[1] + "\0" + paths[0] + "\0",
                    "readlink-alias" => "/alias\0" + paths[1] + "\0",
                    "stat-missing" => string.Join('\0', fields[..4]) + "\0",
                    "stat-extra" => output + output,
                    "stat-reordered" => string.Join('\0', fields[4..8].Concat(fields[..4])) + "\0",
                    _ => AlterStat(fields, failure)
                };
                return new(0, altered, "do-not-log");
            }
        };
        var error = await Assert.ThrowsAsync<MigrationExecutionException>(() => new LocalDockerResourceObserver(process)
            .StatManyAsync(Host, SourceObservationFixture.ContainerId, paths, CancellationToken.None));
        Assert.Equal("source_observation_" + boundary, error.Code);
        Assert.DoesNotContain("do-not-log", error.ToString());
        Assert.Equal(failure.StartsWith("readlink", StringComparison.Ordinal) ? 1 : 2, process.Commands.Count);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task StatMany_CancellationBeforeOrBetweenCommands_StopsWithoutPartialResult(bool during)
    {
        using var cancellation = new CancellationTokenSource();
        var process = new FakeDockerProcess { BatchResult = (_, output) => { cancellation.Cancel(); return new(0, output, ""); } };
        if (!during) { cancellation.Cancel(); }
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new LocalDockerResourceObserver(process)
            .StatManyAsync(Host, SourceObservationFixture.ContainerId, ["/data/a.mdf"], cancellation.Token));
        Assert.Equal(during ? 1 : 0, process.Commands.Count);
    }

    [Fact]
    public async Task StatMany_CallerMutatesInputDuringFirstProcess_UsesValidatedSnapshotForAllBatches()
    {
        string[] paths = Enumerable.Range(0, 33).Select(index => $"/data/{index}.mdf").ToArray();
        string[] original = paths.ToArray();
        var process = new FakeDockerProcess { BatchResult = (_, output) => { paths[^1] = "/../changed"; return new(0, output, ""); } };
        var result = await new LocalDockerResourceObserver(process).StatManyAsync(Host, SourceObservationFixture.ContainerId, paths, CancellationToken.None);
        Assert.Equal(33, result.Length);
        Assert.Equal(original, process.Commands.Where(command => command.Contains("stat")).SelectMany(Paths));
    }

    private static string[] Paths(IReadOnlyList<string> args) { return args.SkipWhile(arg => arg != "--").Skip(1).ToArray(); }

    private static string AlterStat(string[] fields, string failure)
    {
        switch (failure)
        {
            case "stat-alias": fields[4] = "/alias"; break;
            case "stat-symlink": fields[7] = "symbolic link"; break;
            case "stat-directory": fields[7] = "directory"; break;
            case "stat-zero-device": fields[5] = "0"; break;
            case "stat-bad-device": fields[5] = "not-a-device"; break;
            case "stat-zero-inode": fields[6] = "0"; break;
            case "stat-overflow-inode": fields[6] = "18446744073709551616"; break;
            case "stat-space-inode": fields[6] = "903 "; break;
            default: throw new InvalidOperationException();
        }
        return string.Join('\0', fields);
    }
}

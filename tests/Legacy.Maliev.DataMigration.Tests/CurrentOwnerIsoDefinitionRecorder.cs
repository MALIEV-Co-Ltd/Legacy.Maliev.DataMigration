using System.Security.Cryptography;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

// Actual observation instrumentation only. Every slot is immutable and reader held; no passing marker is emitted here.
internal sealed class IsoDefinitionRecorder : IDisposable
{
    private static readonly AsyncLocal<IsoDefinitionRecorder?> Current = new();
    private readonly string _directory;
    private readonly string _caseId;
    private readonly Guid? _run;
    private readonly IsoDefinitionRecorder? _previous;
    internal IsoDefinitionRecorder(string caseId, Guid? run, string? fault)
    {
        // Owner components are separately observed; they do not alter or satisfy the fixed definition proof case inventory.
        bool ownerComponent = caseId is "operand-owner-Country" or "operand-owner-Material";
        if ((!IsoDefinitionCases.Required.Contains(caseId, StringComparer.Ordinal) && !ownerComponent) || caseId == "pure-storage" != (run is null))
        { throw IsoDefinitionCases.Invalid(); }
        _directory = Environment.GetEnvironmentVariable("MALIEV_ISO_DEFINITION_LEDGER") ?? throw IsoDefinitionCases.Invalid();
        if (!Path.IsPathFullyQualified(_directory) || !Directory.Exists(_directory)) { throw IsoDefinitionCases.Invalid(); }
        _caseId = caseId; _run = run; _previous = Current.Value;
        if (_previous is not null) { throw IsoDefinitionCases.Invalid(); }
        using var assembly = SecureLocalFile.OpenReadShared(typeof(IsoDefinitionRecorder).Assembly.Location);
        Write("entered", new IsoDefinitionEntry("iso-definition-entered-v1", caseId, run, fault,
            Convert.ToHexStringLower(SHA256.HashData(assembly)), DateTimeOffset.UtcNow));
        Current.Value = this;
    }
    internal static void Native(string phase, CurrentOwnerIsoNativeObservation observation)
    {
        Require().Write(phase, IsoCapturedNative.Capture(observation));
    }

    internal static void Projection(string database, string phase, string rows, string outside)
    {
        Require().Write(database + "-" + phase, new IsoDefinitionProjection(database, rows, outside));
    }

    internal static void Raw(string phase, CurrentAppOwnedDatabaseSnapshot actual)
    {
        Require().Write(phase, actual);
    }

    internal static void Rejected(string boundary, string code)
    {
        Require().Write("rejected",
            new IsoDefinitionRejection("iso-definition-rejected-v1", Require()._caseId, boundary, code, DateTimeOffset.UtcNow));
    }

    internal static void Resource(string phase, object actual)
    {
        Require().Write("resource-" + phase, actual);
    }

    internal void CompleteInvocation()
    {
        Write("exited", new IsoDefinitionExit("iso-definition-exited-v1", _caseId, _run, DateTimeOffset.UtcNow));
    }

    internal void Write(string phase, object actual)
    {
        if (phase.Length == 0 || phase.Any(x => !char.IsAsciiLetterOrDigit(x) && x != '-' && x != '_')) { throw IsoDefinitionCases.Invalid(); }
        using var file = new FileStream(Path.Combine(_directory, _caseId + "-" + phase + ".json"),
            FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        JsonSerializer.Serialize(file, actual, actual.GetType()); file.Flush(flushToDisk: true);
    }
    public void Dispose() { if (Current.Value != this) { throw IsoDefinitionCases.Invalid(); } Current.Value = _previous; }
    private static IsoDefinitionRecorder Require()
    {
        return Current.Value ?? throw IsoDefinitionCases.Invalid();
    }
}

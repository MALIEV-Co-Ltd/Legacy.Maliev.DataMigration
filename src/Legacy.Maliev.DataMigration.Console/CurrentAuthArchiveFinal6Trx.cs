using System.Xml;
using System.Xml.Linq;

namespace Legacy.Maliev.DataMigration.Console;

internal static class CurrentAuthArchiveFinal6Trx
{
    internal static void Require(byte[] bytes, string methodName, string? expectedAssemblyPath = null)
    {
        using var stream = new MemoryStream(bytes);
        using var reader = XmlReader.Create(stream, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null });
        XDocument document = XDocument.Load(reader); XNamespace ns = "http://microsoft.com/schemas/VisualStudio/TeamTest/2010";
        XElement result = document.Descendants(ns + "UnitTestResult").Single();
        XElement test = document.Descendants(ns + "UnitTest").Single(); XElement method = test.Element(ns + "TestMethod") ?? throw CurrentAuthArchiveFinal6Source.Invalid();
        XElement counters = document.Descendants(ns + "Counters").Single();
        string fullName = "Legacy.Maliev.DataMigration.Tests.CurrentAuthArchiveFinal6GuardedExecutionTests." + methodName;
        if ((string?)result.Attribute("outcome") != "Passed" || ((string?)result.Attribute("testName") != methodName && (string?)result.Attribute("testName") != fullName) ||
            (string?)method.Attribute("name") != methodName || (string?)method.Attribute("className") != "Legacy.Maliev.DataMigration.Tests.CurrentAuthArchiveFinal6GuardedExecutionTests" ||
            (string?)result.Attribute("testId") != (string?)test.Attribute("id") || !Guid.TryParse((string?)result.Attribute("executionId"), out _) ||
            (string?)counters.Attribute("total") != "1" || (string?)counters.Attribute("passed") != "1" || (string?)counters.Attribute("executed") != "1") { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        if (expectedAssemblyPath is not null && (!SamePath((string?)method.Attribute("codeBase"), expectedAssemblyPath) ||
            !SamePath((string?)test.Attribute("storage"), expectedAssemblyPath))) { throw CurrentAuthArchiveFinal6Source.Invalid(); }

        static bool SamePath(string? value, string expected)
        {
            if (string.IsNullOrWhiteSpace(value)) { return false; }
            string path = Uri.TryCreate(value, UriKind.Absolute, out Uri? uri) && uri.IsFile ? uri.LocalPath : value;
            return Path.IsPathFullyQualified(path) && StringComparer.OrdinalIgnoreCase.Equals(Path.GetFullPath(path), Path.GetFullPath(expected));
        }
    }
}

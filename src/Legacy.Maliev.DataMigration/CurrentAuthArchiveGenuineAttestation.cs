using System.Text.Json.Serialization;

namespace Legacy.Maliev.DataMigration;

// Data returned by one fixed, authenticated Console issuer method. This record is
// not a capability and its construction never grants authority.
internal sealed record CurrentAuthArchiveGenuineAttestation(string Phase, string CaseId,
    CurrentAuthArchiveScope Scope, CurrentAuthArchiveComponentBootstrapSubject Subject, FreshSchemaPlan Source,
    string TestImagePath, string ConsoleImagePath, string CoreImagePath, CurrentAuthArchivePins Pins,
    [property: JsonIgnore] IReceiptAttestationTrustStore Trust,
    [property: JsonIgnore] ICurrentAuthLocalSessionArchiveEnvironment Environment);

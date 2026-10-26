namespace Legacy.Maliev.DataMigration;

// Signed into the named disposable scope; independent precursor artifacts retain their own
// subject/root/signing keys. No future closed proof digest is included or invented.
internal sealed record CurrentOwnerIsoClosedPrecursorPins(string RootBindingSha256, string DefinitionSubjectSha256,
    string DefinitionProofSha256, string ProofKeyId, string ProofFingerprint,
    string DefinitionKeyId, string DefinitionFingerprint);

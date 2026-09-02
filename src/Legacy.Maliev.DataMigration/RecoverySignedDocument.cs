using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Legacy.Maliev.DataMigration;

public abstract class RecoverySignedDocument<T>
{
    private readonly RecoveryDocumentEnvelope _envelope;
    private protected RecoverySignedDocument(string exactJson, string domain)
    {
        _envelope = RecoveryContractEncoding.Parse<RecoveryDocumentEnvelope>(exactJson);
        RecoveryContractEncoding.Require(_envelope.Domain == domain && _envelope.Version == "1.0" &&
            !string.IsNullOrWhiteSpace(_envelope.AttestationKeyId) && _envelope.AttestationSignature.Length is > 0 and <= 4096,
            "The signed recovery document domain, version or signature is invalid.");
        Payload = RecoveryContractEncoding.Parse<T>(_envelope.PayloadJson);
        // New payloads have a strict canonical wire shape. In particular, serializers must not silently
        // ignore contradictory getter-only fields. This rule never rewrites retained historical JSON.
        RecoveryContractEncoding.Require(RecoveryContractEncoding.Serialize(Payload) == _envelope.PayloadJson,
            "The signed recovery payload is noncanonical or contains ignored field values.");
        ExactJson = exactJson;
    }

    /// <summary>Persist this exact text, never JSONB or a reserialized payload. Its digest includes the signature.</summary>
    public string ExactJson { get; }
    public T Payload { get; }
    public string AttestationKeyId => _envelope.AttestationKeyId;
    public string ComputeSha256()
    {
        return RecoveryContractEncoding.Digest(_envelope.Domain + ".SignedDocument", ExactJson);
    }

    internal void Verify(IReceiptAttestationTrustStore trust, string expectedKeyId)
    {
        try
        {
            RecoveryContractEncoding.Require(AttestationKeyId == expectedKeyId && trust.ContainsKey(expectedKeyId) &&
                trust.Verify(expectedKeyId, RecoveryContractEncoding.SigningBytes(_envelope), Convert.FromBase64String(_envelope.AttestationSignature)),
                "The signed recovery document is untrusted or uses the wrong signing role.");
        }
        catch (FormatException exception) { throw RecoveryContractEncoding.Invalid("The recovery signature is malformed.", exception); }
    }

    private protected static string SignDocument(T payload, IMigrationEvidenceSigner signer, string domain)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(signer);
        // Serialize once before signing. No caller-owned object participates in later verification or persistence.
        string json = RecoveryContractEncoding.Serialize(payload);
        _ = RecoveryContractEncoding.Parse<T>(json);
        var envelope = new RecoveryDocumentEnvelope(domain, "1.0", json, signer.KeyId, "");
        envelope = envelope with { AttestationSignature = Convert.ToBase64String(signer.Sign(RecoveryContractEncoding.SigningBytes(envelope))) };
        return JsonSerializer.Serialize(envelope, RecoveryContractEncoding.Options);
    }
}

public sealed class InitialMigrationAdmission : RecoverySignedDocument<InitialMigrationAdmissionPayload>
{
    private const string Domain = "Legacy.Maliev.DataMigration.InitialAdmission.v1";
    private InitialMigrationAdmission(string json) : base(json, Domain) { }
    public static InitialMigrationAdmission Parse(string exactJson)
    {
        return new(exactJson);
    }

    public static InitialMigrationAdmission Sign(InitialMigrationAdmissionPayload payload, IMigrationEvidenceSigner signer)
    {
        return new(SignDocument(payload, signer, Domain));
    }
}

/// <summary>Externally supplied provenance; no runtime observer or resume-preparation API creates this document.</summary>
public sealed class SourceContinuityAttestation : RecoverySignedDocument<SourceContinuityPayload>
{
    private const string Domain = "Legacy.Maliev.DataMigration.SourceContinuity.v1";
    private SourceContinuityAttestation(string json) : base(json, Domain) { }
    public static SourceContinuityAttestation Parse(string exactJson)
    {
        return new(exactJson);
    }

    /// <summary>Signs an explicit external provenance assertion. This does not derive history from observations.</summary>
    public static SourceContinuityAttestation Sign(SourceContinuityPayload payload, IMigrationEvidenceSigner signer)
    {
        return new(SignDocument(payload, signer, Domain));
    }
}

public sealed class ResumeAuthorizationReceipt : RecoverySignedDocument<ResumeAuthorizationPayload>
{
    private const string Domain = "Legacy.Maliev.DataMigration.ResumeAuthorization.v1";
    private ResumeAuthorizationReceipt(string json) : base(json, Domain) { }
    public static ResumeAuthorizationReceipt Parse(string exactJson)
    {
        return new(exactJson);
    }

    public static ResumeAuthorizationReceipt Sign(ResumeAuthorizationPayload payload, IMigrationEvidenceSigner signer)
    {
        return new(SignDocument(payload, signer, Domain));
    }
}

internal sealed record RecoveryDocumentEnvelope(string Domain, string Version, string PayloadJson, string AttestationKeyId, string AttestationSignature);

internal static class RecoveryContractEncoding
{
    internal static readonly JsonSerializerOptions Options = new()
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectRequiredConstructorParameters = true,
        RespectNullableAnnotations = true,
        AllowDuplicateProperties = false,
    };

    internal static T Parse<T>(string json)
    {
        try
        {
            Require(json is not null && json.Length is > 0 and <= 64 * 1024 * 1024, "The recovery JSON document is missing or too large.");
            using JsonDocument document = JsonDocument.Parse(json!);
            RejectNullArrayItems(document.RootElement);
            return JsonSerializer.Deserialize<T>(json!, Options) ?? throw Invalid("The recovery JSON document is null.");
        }
        catch (Exception exception) when (exception is JsonException or NotSupportedException or ArgumentException)
        { throw Invalid("The recovery JSON document is malformed or contains unapproved fields.", exception); }
    }

    internal static string Serialize<T>(T value)
    {
        try { return JsonSerializer.Serialize(value, Options); }
        catch (Exception exception) when (exception is JsonException or NotSupportedException or ArgumentException)
        { throw Invalid("The recovery contract contains malformed fields.", exception); }
    }

    private static void RejectNullArrayItems(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement item in value.EnumerateArray())
            {
                Require(item.ValueKind != JsonValueKind.Null, "The recovery contract contains a null collection item.");
                RejectNullArrayItems(item);
            }
        }
        else if (value.ValueKind == JsonValueKind.Object)
        {
            foreach (JsonProperty property in value.EnumerateObject()) { RejectNullArrayItems(property.Value); }
        }
    }

    internal static byte[] SigningBytes(RecoveryDocumentEnvelope value)
    {
        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream, new UTF8Encoding(false, true), leaveOpen: true))
        {
            writer.Write(value.Domain); writer.Write(value.Version); writer.Write(value.AttestationKeyId); writer.Write(value.PayloadJson);
        }
        return stream.ToArray();
    }

    internal static string Digest(string domain, string value)
    {
        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream, new UTF8Encoding(false, true), leaveOpen: true)) { writer.Write(domain); writer.Write(value); }
        return Hash(stream.ToArray());
    }
    internal static string Hash(byte[] bytes)
    {
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }

    internal static void Require(bool condition, string message) { if (!condition) { throw Invalid(message); } }
    internal static MigrationExecutionException Invalid(string message, Exception? inner = null)
    {
        return new("recovery_authority_invalid", message, inner);
    }
}

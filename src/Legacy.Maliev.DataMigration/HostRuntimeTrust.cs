using System.Formats.Asn1;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Legacy.Maliev.DataMigration;

internal static class HostRuntimeTrust
{
    internal static string ReadText(string path)
    {
        try
        {
            if (!Path.IsPathFullyQualified(path) || path.StartsWith("\\\\", StringComparison.Ordinal)) { throw Invalid(); }
            using FileStream stream = SecureLocalFile.OpenReadShared(path);
            using var reader = new StreamReader(stream);
            return reader.ReadToEnd();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or Exact25FullBackupException)
        { throw Invalid(); }
    }

    internal static X509Certificate2Collection ReadAuthorities(string path)
    {
        var roots = new X509Certificate2Collection();
        try
        {
            roots.ImportFromPem(ReadText(path));
            return roots.Count == 0 || roots.Cast<X509Certificate2>().Any(root =>
                !root.Extensions.OfType<X509BasicConstraintsExtension>().Any(extension => extension.CertificateAuthority))
                ? throw Invalid()
                : roots;
        }
        catch (Exception exception)
        {
            foreach (X509Certificate2 root in roots) { root.Dispose(); }
            if (exception is CryptographicException) { throw Invalid(); }
            throw;
        }
    }

    internal static HttpMessageHandler CreateKubernetesHandler(Uri endpoint, string tokenPath, string caPath)
    {
        if (endpoint is null || !endpoint.IsAbsoluteUri || endpoint.Scheme != Uri.UriSchemeHttps ||
            endpoint.HostNameType != UriHostNameType.Dns || endpoint.AbsolutePath != "/" ||
            endpoint.UserInfo.Length != 0 || endpoint.Query.Length != 0 || endpoint.Fragment.Length != 0)
        { throw Invalid(); }
        if (string.IsNullOrWhiteSpace(ReadText(tokenPath))) { throw Invalid(); }
        try { return new ProtectedTlsHandler(ReadAuthorities(caPath)); }
        catch (CryptographicException) { throw Invalid(); }
    }

    // This entry point is reserved for the signed current-app-owned repair composition.
    // IP SAN verification uses the unchanged TLS handler and actual URI destination.
    internal static HttpMessageHandler CreateRepairKubernetesIpv4Handler(Uri endpoint, string tokenPath, string caPath)
    {
        if (endpoint is null || !endpoint.IsAbsoluteUri || endpoint.Scheme != Uri.UriSchemeHttps ||
            endpoint.HostNameType != UriHostNameType.IPv4 || endpoint.AbsolutePath != "/" ||
            endpoint.UserInfo.Length != 0 || endpoint.Query.Length != 0 || endpoint.Fragment.Length != 0)
        { throw Invalid(); }
        if (string.IsNullOrWhiteSpace(ReadText(tokenPath))) { throw Invalid(); }
        try { return new ProtectedTlsHandler(ReadAuthorities(caPath), IPAddress.Parse(endpoint.Host)); }
        catch (CryptographicException) { throw Invalid(); }
    }

    internal static bool HasMatchingIpSan(X509Certificate2 certificate, IPAddress expected)
    {
        X509Extension[] extensions = [.. certificate.Extensions.Cast<X509Extension>().Where(x => x.Oid?.Value == "2.5.29.17")];
        if (extensions.Length != 1) { return false; }
        try
        {
            var reader = new AsnReader(extensions[0].RawData, AsnEncodingRules.DER);
            AsnReader names = reader.ReadSequence();
            bool matches = false;
            while (names.HasData)
            {
                Asn1Tag tag = names.PeekTag();
                if (tag.TagClass != TagClass.ContextSpecific || tag.TagValue is < 0 or > 8) { return false; }
                if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 7)))
                {
                    byte[] address = names.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 7));
                    if (address.Length is not (4 or 16)) { return false; }
                    if (address.AsSpan().SequenceEqual(expected.GetAddressBytes())) { matches = true; }
                }
                else { _ = names.ReadEncodedValue(); }
            }
            reader.ThrowIfNotEmpty();
            return matches;
        }
        catch (AsnContentException) { return false; }
    }

    internal static MigrationExecutionException Invalid()
    {
        return new("host_runtime_reference_invalid",
        "Host runtime requires explicit protected local trust files and an authenticated endpoint hostname.");
    }

    private sealed class ProtectedTlsHandler : DelegatingHandler
    {
        private readonly X509Certificate2Collection _roots;
        internal ProtectedTlsHandler(X509Certificate2Collection roots, IPAddress? requiredIpSan = null)
        {
            _roots = roots;
            InnerHandler = new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                UseProxy = false,
                ConnectTimeout = TimeSpan.FromSeconds(15),
                SslOptions = new()
                {
                    RemoteCertificateValidationCallback = (_, certificate, _, errors) =>
                    {
                        if (certificate is null || (errors & (SslPolicyErrors.RemoteCertificateNameMismatch | SslPolicyErrors.RemoteCertificateNotAvailable)) != 0) { return false; }
                        using var chain = new X509Chain();
                        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                        chain.ChainPolicy.CustomTrustStore.AddRange(_roots);
                        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                        _ = chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
                        using var leaf = new X509Certificate2(certificate);
                        return (requiredIpSan is null || HasMatchingIpSan(leaf, requiredIpSan)) && chain.Build(leaf);
                    },
                },
            };
        }
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (disposing) { foreach (X509Certificate2 root in _roots) { root.Dispose(); } }
        }
    }
}

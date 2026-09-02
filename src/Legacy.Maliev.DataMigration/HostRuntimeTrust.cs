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

    internal static MigrationExecutionException Invalid()
    {
        return new("host_runtime_reference_invalid",
        "Host runtime requires explicit protected local trust files and an authenticated endpoint hostname.");
    }

    private sealed class ProtectedTlsHandler : DelegatingHandler
    {
        private readonly X509Certificate2Collection _roots;
        internal ProtectedTlsHandler(X509Certificate2Collection roots)
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
                        return chain.Build(leaf);
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

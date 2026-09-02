using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Legacy.Maliev.DataMigration.Tests;

internal sealed class HostTlsTestServer : IAsyncDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _serving;
    internal string Root { get; } = Path.Combine(Path.GetTempPath(), $"host-tls-{Guid.NewGuid():N}");
    internal string CaPath => Path.Combine(Root, "ca.pem");
    internal string TokenPath => Path.Combine(Root, "token");
    internal X509Certificate2 Ca { get; }
    internal X509Certificate2 Server { get; }
    internal Uri Address { get; }
    internal int Requests { get; private set; }
    internal string? Authorization { get; private set; }
    internal string? LastFailure { get; private set; }
    internal string ResponseBody { get; set; } = string.Empty;
    internal int ResponseStatusCode { get; set; } = 503;

    internal HostTlsTestServer(string name = "localhost")
    {
        SecureSnapshotFileCreation.CreateRestrictedDirectory(Root);
        using RSA caKey = RSA.Create(2048);
        var caRequest = new CertificateRequest("CN=Disposable Host Test CA", caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        Ca = caRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        using RSA key = RSA.Create(2048);
        var request = new CertificateRequest($"CN={name}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder(); san.AddDnsName(name);
        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new("1.3.6.1.5.5.7.3.1")], true));
        using X509Certificate2 issued = request.Create(Ca, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddHours(12), RandomNumberGenerator.GetBytes(16));
        using X509Certificate2 withKey = issued.CopyWithPrivateKey(key);
        Server = X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pkcs12), null, X509KeyStorageFlags.Exportable);
        File.WriteAllText(CaPath, Ca.ExportCertificatePem());
        File.WriteAllText(TokenPath, "synthetic.bound.token");
        _listener.Start();
        Address = new Uri($"https://localhost:{((IPEndPoint)_listener.LocalEndpoint).Port}");
        _serving = ServeAsync();
    }

    private async Task ServeAsync()
    {
        while (!_stop.IsCancellationRequested)
        {
            try
            {
                using TcpClient client = await _listener.AcceptTcpClientAsync(_stop.Token);
                using var tls = new SslStream(client.GetStream());
                await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = Server }, _stop.Token);
                using var reader = new StreamReader(tls, leaveOpen: true);
                while (await reader.ReadLineAsync(_stop.Token) is { Length: > 0 } line)
                {
                    if (line.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase)) { Authorization = line; }
                }
                Requests++;
                byte[] body = Encoding.UTF8.GetBytes(ResponseBody);
                await tls.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 {ResponseStatusCode} Fixture\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n"), _stop.Token);
                await tls.WriteAsync(body, _stop.Token);
            }
            catch (Exception exception) when (exception is AuthenticationException or IOException or OperationCanceledException or SocketException)
            { LastFailure = exception.ToString(); }
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync(); _listener.Stop(); await _serving;
        _stop.Dispose(); Server.Dispose(); Ca.Dispose(); Directory.Delete(Root, true);
    }
}

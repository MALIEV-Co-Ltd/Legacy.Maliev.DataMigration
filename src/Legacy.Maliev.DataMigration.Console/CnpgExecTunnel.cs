using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CnpgExecTunnelConfiguration(
    string Context,
    string ClusterUid,
    long ClusterGeneration,
    string PrimaryPod,
    string PrimaryPodUid,
    int ListenPort);

internal static class CnpgExecTunnel
{
    private const string RequiredContext = "gke_maliev-website_us-central1-a_web-production-cluster";
    private const string Namespace = "maliev-legacy";
    private const string Cluster = "legacy-postgres-main";
    private const string Container = "postgres";
    private const string Relay = "exec 3<>/dev/tcp/127.0.0.1/5432; cat <&0 >&3 & forward=$!; cat <&3 >&1; kill \"$forward\" 2>/dev/null || true";
    private static readonly JsonSerializerOptions ConfigurationJsonOptions = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow,
    };

    internal static Task RunAsync(string configPath, Func<string, string?> environment, TextWriter output, TextWriter error, CancellationToken ct)
    {
        return RunCoreAsync(configPath, environment, output, error, null, ct);
    }

    internal static Task RunOwnedAsync(string configPath, TextWriter output, TextWriter error, DualTargetCapturedToolLease tools, CancellationToken ct)
    {
        return RunCoreAsync(configPath, Environment.GetEnvironmentVariable, output, error, tools, ct);
    }

    internal static Task VerifyTargetAsync(CnpgExecTunnelConfiguration config, CancellationToken ct)
    {
        return VerifyTargetCoreAsync(config, null, ct);
    }

    private static async Task RunCoreAsync(
        string configPath,
        Func<string, string?> environment,
        TextWriter output,
        TextWriter error,
        DualTargetCapturedToolLease? tools,
        CancellationToken cancellationToken)
    {
        if (!string.Equals(environment("LEGACY_DEPLOY_ENABLED"), "false", StringComparison.Ordinal))
        {
            throw new MigrationConsoleException("cnpg_exec_tunnel_deploy_gate_invalid", "Deployment must remain disabled.");
        }

        CnpgExecTunnelConfiguration config;
        try
        {
            config = JsonSerializer.Deserialize<CnpgExecTunnelConfiguration>(
                await File.ReadAllTextAsync(configPath, cancellationToken).ConfigureAwait(false),
                ConfigurationJsonOptions) ?? throw new JsonException("Configuration is empty.");
        }
        catch (Exception exception) when (exception is IOException or JsonException or UnauthorizedAccessException)
        {
            throw new MigrationConsoleException("cnpg_exec_tunnel_config_invalid", "The tunnel configuration is unavailable or invalid.");
        }

        Validate(config);
        await VerifyTargetCoreAsync(config, tools, cancellationToken).ConfigureAwait(false);

        using var listener = new TcpListener(IPAddress.Loopback, config.ListenPort);
        using var slots = new SemaphoreSlim(32);
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        void cancel(object? _, ConsoleCancelEventArgs args) { args.Cancel = true; stop.Cancel(); }
        System.Console.CancelKeyPress += cancel;
        var active = new List<Task>();
        try
        {
            listener.Start(32);
            await output.WriteLineAsync("cnpg_exec_tunnel_ready").ConfigureAwait(false);
            while (!stop.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await listener.AcceptTcpClientAsync(stop.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (stop.IsCancellationRequested)
                {
                    break;
                }

                if (!await slots.WaitAsync(0, stop.Token).ConfigureAwait(false))
                {
                    client.Dispose();
                    continue;
                }

                _ = active.RemoveAll(task => task.IsCompleted);
                active.Add(HandleAsync(client, config, tools, error, stop, slots));
            }
        }
        finally
        {
            System.Console.CancelKeyPress -= cancel;
            listener.Stop();
            stop.Cancel();
            await Task.WhenAll(active).ConfigureAwait(false);
        }
    }

    internal static void Validate(CnpgExecTunnelConfiguration config)
    {
        if (!string.Equals(config.Context, RequiredContext, StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(config.ClusterUid) ||
            config.ClusterGeneration <= 0 ||
            string.IsNullOrWhiteSpace(config.PrimaryPod) ||
            string.IsNullOrWhiteSpace(config.PrimaryPodUid) ||
            config.ListenPort is < 1024 or > 65535)
        {
            throw new MigrationConsoleException("cnpg_exec_tunnel_config_invalid", "The tunnel target or listener is invalid.");
        }
    }

    private static async Task HandleAsync(
        TcpClient client,
        CnpgExecTunnelConfiguration config,
        DualTargetCapturedToolLease? tools,
        TextWriter error,
        CancellationTokenSource stop,
        SemaphoreSlim slots)
    {
        using (client)
        {
            try
            {
                // Recheck immutable Kubernetes identity for every PostgreSQL connection.
                await VerifyTargetCoreAsync(config, tools, stop.Token).ConfigureAwait(false);
                using Process process = StartKubectl(
                    ["-n", Namespace, "exec", "-i", config.PrimaryPod, "-c", Container, "--", "bash", "-c", Relay], tools);
                Task stderr = DrainAsync(process.StandardError, stop.Token);
                using NetworkStream network = client.GetStream();
                Task upstream = network.CopyToAsync(process.StandardInput.BaseStream, stop.Token);
                Task downstream = process.StandardOutput.BaseStream.CopyToAsync(network, stop.Token);
                await CloseRelayOnCompletionAsync(network, upstream, downstream).ConfigureAwait(false);
                bool kubectlFailed = process.HasExited && process.ExitCode != 0;
                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                }
                await process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
                await ObserveRelayTasksAsync(upstream, downstream, stderr).ConfigureAwait(false);
                if (kubectlFailed)
                {
                    throw new MigrationConsoleException("cnpg_exec_tunnel_transport_failed", "The Kubernetes stream closed unexpectedly.");
                }
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested)
            {
                // Normal shutdown; the client socket is disposed below.
            }
            catch (Exception exception) when (exception is IOException or SocketException or InvalidOperationException or
                MigrationConsoleException or JsonException or KeyNotFoundException or System.ComponentModel.Win32Exception)
            {
                await error.WriteLineAsync($"cnpg_exec_tunnel_connection_failed:{FailureCode(exception)}")
                    .ConfigureAwait(false);
                stop.Cancel();
            }
            finally
            {
                _ = slots.Release();
            }
        }
    }

    internal static string FailureCode(Exception exception)
    {
        return exception switch
        {
            MigrationConsoleException migration => migration.Code,
            SocketException => "socket_error",
            IOException => "io_error",
            JsonException => "observation_json_invalid",
            KeyNotFoundException => "observation_field_missing",
            System.ComponentModel.Win32Exception => "kubectl_start_failed",
            _ => "relay_state_invalid",
        };
    }

    internal static async Task CloseRelayOnCompletionAsync(Stream network, Task upstream, Task downstream)
    {
        _ = await Task.WhenAny(upstream, downstream).ConfigureAwait(false);
        // Either EOF terminates this one PostgreSQL relay. Close the client stream
        // before joining the losing copy: after remote EOF it can still be waiting
        // for input from a client that is itself waiting for a query response.
        network.Close();
    }

    private static async Task ObserveRelayTasksAsync(params Task[] tasks)
    {
        foreach (Task task in tasks)
        {
            try { await task.ConfigureAwait(false); }
            catch (Exception exception) when (exception is IOException or ObjectDisposedException or OperationCanceledException)
            {
                // Closing the connection interrupts the losing relay direction.
            }
        }
    }

    private static async Task DrainAsync(StreamReader reader, CancellationToken cancellationToken)
    {
        char[] buffer = new char[1024];
        while (await reader.ReadAsync(buffer, cancellationToken).ConfigureAwait(false) > 0)
        {
            // kubectl stderr may contain sensitive environment details; never persist it.
        }
    }

    private static async Task VerifyTargetCoreAsync(CnpgExecTunnelConfiguration config, DualTargetCapturedToolLease? tools, CancellationToken cancellationToken)
    {
        if (tools is not null) { await tools.RequireCredentialProtocolAsync(cancellationToken).ConfigureAwait(false); }
        string context = (await KubectlOutputAsync(["config", "current-context"], tools, cancellationToken).ConfigureAwait(false)).Trim();
        if (!string.Equals(context, config.Context, StringComparison.Ordinal))
        {
            throw new MigrationConsoleException("cnpg_exec_tunnel_context_drift", "The Kubernetes context changed.");
        }

        try
        {
            using JsonDocument cluster = JsonDocument.Parse(await KubectlOutputAsync(
                ["-n", Namespace, "get", "cluster", Cluster, "-o", "json"], tools, cancellationToken).ConfigureAwait(false));
            using JsonDocument pod = JsonDocument.Parse(await KubectlOutputAsync(
                ["-n", Namespace, "get", "pod", config.PrimaryPod, "-o", "json"], tools, cancellationToken).ConfigureAwait(false));
            ValidateObservation(config, cluster.RootElement, pod.RootElement);
        }
        catch (Exception exception) when (exception is JsonException or KeyNotFoundException or InvalidOperationException)
        {
            throw new MigrationConsoleException("cnpg_exec_tunnel_observation_invalid", "Kubernetes target observation is invalid.");
        }
    }

    internal static void ValidateObservation(CnpgExecTunnelConfiguration config, JsonElement clusterRoot, JsonElement podRoot)
    {
        JsonElement clusterStatus = clusterRoot.GetProperty("status");
        if (!string.Equals(clusterRoot.GetProperty("metadata").GetProperty("uid").GetString(), config.ClusterUid, StringComparison.Ordinal) ||
            clusterRoot.GetProperty("metadata").GetProperty("generation").GetInt64() != config.ClusterGeneration ||
            !string.Equals(clusterStatus.GetProperty("phase").GetString(), "Cluster in healthy state", StringComparison.Ordinal) ||
            clusterStatus.GetProperty("readyInstances").GetInt32() != 2 ||
            clusterStatus.GetProperty("instances").GetInt32() != 2 ||
            !clusterStatus.GetProperty("conditions").EnumerateArray().Any(condition =>
                string.Equals(condition.GetProperty("type").GetString(), "ContinuousArchiving", StringComparison.Ordinal) &&
                string.Equals(condition.GetProperty("status").GetString(), "True", StringComparison.Ordinal)) ||
            !string.Equals(clusterStatus.GetProperty("currentPrimary").GetString(), config.PrimaryPod, StringComparison.Ordinal))
        {
            throw new MigrationConsoleException("cnpg_exec_tunnel_cluster_drift", "The target cluster changed or is unhealthy.");
        }

        if (!string.Equals(podRoot.GetProperty("metadata").GetProperty("uid").GetString(), config.PrimaryPodUid, StringComparison.Ordinal) ||
            !string.Equals(podRoot.GetProperty("metadata").GetProperty("labels").GetProperty("cnpg.io/instanceRole").GetString(), "primary", StringComparison.Ordinal) ||
            !string.Equals(podRoot.GetProperty("status").GetProperty("phase").GetString(), "Running", StringComparison.Ordinal))
        {
            throw new MigrationConsoleException("cnpg_exec_tunnel_pod_drift", "The primary pod changed or is unhealthy.");
        }
    }

    private static async Task<string> KubectlOutputAsync(IReadOnlyList<string> arguments, DualTargetCapturedToolLease? tools, CancellationToken cancellationToken)
    {
        using Process process = StartKubectl(arguments, tools);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        // Twenty-three held SQL Server snapshots can contend with the target's
        // Kubernetes admission query. Keep the identity check strict while
        // allowing the observation enough time under that load.
        timeout.CancelAfter(TimeSpan.FromSeconds(60));
        Task<string> stdout = process.StandardOutput.ReadToEndAsync(timeout.Token);
        Task stderr = DrainAsync(process.StandardError, timeout.Token);
        try
        {
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            string result = await stdout.ConfigureAwait(false);
            await stderr.ConfigureAwait(false);
            return process.ExitCode != 0 || result.Length > 1024 * 1024
                ? throw new MigrationConsoleException("cnpg_exec_tunnel_observation_failed", "Kubernetes target observation failed.")
                : result;
        }
        catch (OperationCanceledException)
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }

            throw new MigrationConsoleException("cnpg_exec_tunnel_observation_timeout", "Kubernetes target observation timed out.");
        }
    }

    private static Process StartKubectl(IReadOnlyList<string> arguments, DualTargetCapturedToolLease? tools)
    {
        var start = new ProcessStartInfo(tools?.KubectlPath ?? "kubectl")
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        foreach (string argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }
        if (tools is not null)
        {
            tools.Require();
            start.Environment["PATH"] = Path.GetDirectoryName(DualTargetCapturedToolLease.CredentialPlugin) + Path.PathSeparator + Environment.SystemDirectory;
        }

        try
        {
            return Process.Start(start) ?? throw new MigrationConsoleException(
                "cnpg_exec_tunnel_kubectl_missing", "kubectl could not start.");
        }
        catch (System.ComponentModel.Win32Exception)
        {
            throw new MigrationConsoleException("cnpg_exec_tunnel_kubectl_missing", "kubectl could not start.");
        }
    }
}

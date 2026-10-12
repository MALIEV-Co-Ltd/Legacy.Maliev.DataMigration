using System.Net;
using System.Net.Sockets;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CnpgExecTunnelRelayLifecycleTests
{
    [Fact]
    public async Task Active_directions_keep_connection_open_until_one_completes()
    {
        using var network = new MemoryStream();
        var upstream = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var downstream = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task closing = CnpgExecTunnel.CloseRelayOnCompletionAsync(network, upstream.Task, downstream.Task);
        Assert.False(closing.IsCompleted);
        Assert.True(network.CanRead);
        upstream.SetResult();
        await closing.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.False(network.CanRead);
        downstream.SetResult();
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Either_direction_eof_closes_client_socket_and_unblocks_waiting_read(bool downstreamEof)
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var peer = new TcpClient();
        Task connecting = peer.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);
        using TcpClient accepted = await listener.AcceptTcpClientAsync();
        await connecting;
        using NetworkStream network = accepted.GetStream();
        Task blockedRead = network.CopyToAsync(Stream.Null);
        Task upstream = downstreamEof ? blockedRead : Task.CompletedTask;
        Task downstream = downstreamEof ? Task.CompletedTask : blockedRead;
        Assert.False(blockedRead.IsCompleted);
        await CnpgExecTunnel.CloseRelayOnCompletionAsync(network, upstream, downstream);
        try
        {
            try { await blockedRead.WaitAsync(TimeSpan.FromSeconds(2)); }
            catch (Exception failure) when (failure is IOException or ObjectDisposedException) { }
            Assert.True(blockedRead.IsCompleted, "The losing relay direction must finish without peer EOF or global cancellation.");
            byte[] probe = new byte[1];
            Assert.Equal(0, await peer.GetStream().ReadAsync(probe).AsTask().WaitAsync(TimeSpan.FromSeconds(2)));
        }
        finally
        {
            network.Close();
            try { await blockedRead; }
            catch (Exception failure) when (failure is IOException or ObjectDisposedException) { }
        }
    }
}

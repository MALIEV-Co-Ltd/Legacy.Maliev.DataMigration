using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

internal sealed record ConsumerColumnBootstrapNativePreimagePin(string Database, string Sha256, int ProviderVersion,
    string CompositeDefense, ulong ObservedWalUpper, DateTimeOffset ObservedAtUtc, ConsumerColumnBootstrapProviderObservation Provider);

/// <summary>Target-instance physical preimage; never substituted with IDs from disposable proof fixtures.</summary>
internal static class ConsumerColumnBootstrapNativePreimage
{
    internal static ConsumerColumnBootstrapNativePreimagePin Pin(ConsumerColumnBootstrapPreservationObservation before,
        ConsumerColumnBootstrapProviderObservation provider, DateTimeOffset observedAtUtc)
    {
        if (before.After || observedAtUtc.Offset != TimeSpan.Zero) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        ConsumerColumnBootstrapProviderCompatibility.RequireObservation(provider);
        return provider.EngineVersion != before.ProviderVersion || provider.CompositeDefense != before.CompositeDefense
            ? throw ConsumerColumnBootstrapOperationalContract.Invalid()
            : new(before.LogicalDatabase, Compute(before, provider), before.ProviderVersion, before.CompositeDefense, before.WalUpper, observedAtUtc, provider);
    }

    internal static void Require(ConsumerColumnBootstrapNativePreimagePin reviewed, ConsumerColumnBootstrapPreservationObservation lockedBefore,
        ConsumerColumnBootstrapProviderObservation actualProvider, DateTimeOffset now)
    {
        ConsumerColumnBootstrapProviderCompatibility.RequireObservation(actualProvider);
        if (reviewed.Database != lockedBefore.LogicalDatabase || lockedBefore.After || reviewed.Sha256 != Compute(lockedBefore, actualProvider) ||
            reviewed.Provider != actualProvider ||
            reviewed.ProviderVersion != lockedBefore.ProviderVersion || reviewed.CompositeDefense != lockedBefore.CompositeDefense ||
            reviewed.ObservedWalUpper == 0 || lockedBefore.WalUpper < reviewed.ObservedWalUpper || reviewed.ObservedAtUtc > now ||
            now - reviewed.ObservedAtUtc > TimeSpan.FromMinutes(15)) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        // RequirePreserved subsequently receives this actual locked observation. Its WAL lower
        // bound is never replaced by the older review observation.
    }

    private static string Compute(ConsumerColumnBootstrapPreservationObservation observation, ConsumerColumnBootstrapProviderObservation provider)
    {
        var indexes = observation.Native.Read("pg_class").Where(row => row["relkind"]?.ToString() == "i")
            .Select(row => row["oid"]?.ToString() ?? throw ConsumerColumnBootstrapOperationalContract.Invalid())
            .Order(StringComparer.Ordinal).Select(oid =>
            {
                var (FileNode, Blocks) = observation.Native.Storage(oid);
                return new { Oid = oid, FileNode, Blocks };
            }).ToArray();
        return ConsumerColumnBootstrapOperationalContract.Hash([.. "Legacy.Maliev.ConsumerColumnBootstrap.NativePreimage.v1\0"u8,
            .. JsonSerializer.SerializeToUtf8Bytes(new
            {
                observation.LogicalDatabase, observation.Native.Snapshot.Sha256, observation.ContractSha256,
                observation.OriginalRows, observation.ProviderVersion, observation.CompositeDefense, Provider = provider,
                Heaps = observation.HeapStorage.OrderBy(pair => pair.Key, StringComparer.Ordinal)
                    .Select(pair => new { Relation = pair.Key, pair.Value.File, pair.Value.Blocks }).ToArray(), Indexes = indexes,
            })]);
    }
}

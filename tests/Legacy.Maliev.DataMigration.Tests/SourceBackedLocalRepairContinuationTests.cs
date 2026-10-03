using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class SourceBackedLocalRepairContinuationTests
{
    [Fact]
    public async Task Exact23RetainedChainPreservesAppliedEvidenceAndNeverAuthorizesExecution()
    {
        using var fixture = new Fixture();
        _ = await fixture.Reserve();
        SourceBackedLocalRepairContinuation? previous = null;
        for (int ordinal = 1; ordinal <= 24; ordinal++)
        {
            SourceBackedLocalRepairContinuation value = fixture.Create(ordinal, previous);
            SourceBackedLocalRepairContinuation retained = await fixture.Append(value);
            Assert.Equal(JsonSerializer.Serialize(value), JsonSerializer.Serialize(retained));
            previous = retained;
        }
        Assert.Equal(24, fixture.Gateway.Names.Count(name => name.Contains("/continuations/", StringComparison.Ordinal)));
        Assert.All(previous!.Databases, item => Assert.Equal(SourceBackedLocalRepairPhase.Applied, item.Phase));
        Assert.False(SourceBackedLocalRepairContinuation.AuthorizesExecution);
        Assert.DoesNotContain(fixture.Gateway.Names, name => name.Contains("old-receipts", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("claim")]
    [InlineData("preimage")]
    [InlineData("capture")]
    [InlineData("plan")]
    [InlineData("generation")]
    [InlineData("auth")]
    [InlineData("ordinal")]
    [InlineData("inventory")]
    [InlineData("prior")]
    [InlineData("earlyapply")]
    public async Task TrustedResignedWrongBindingFailsBeforeCreate(string mutation)
    {
        using var fixture = new Fixture();
        _ = await fixture.Reserve();
        SourceBackedLocalRepairContinuation value = fixture.Create(1);
        value = fixture.Sign(mutation switch
        {
            "claim" => value with { ClaimId = Guid.NewGuid() },
            "preimage" => value with { InitialPreimageSha256 = Hash('9') },
            "capture" => value with { SourceCaptureSha256 = Hash('9') },
            "plan" => value with { FuturePlanSha256 = Hash('9') },
            "generation" => value with { TargetGeneration = "docker:changed" },
            "auth" => value with { AuthorizationId = Guid.NewGuid() },
            "ordinal" => value with { Ordinal = 25 },
            "inventory" => value with { Databases = value.Databases.Reverse().ToArray() },
            "prior" => value with { Databases = value.Databases.Select((state, index) => index == 0 ? state with { PriorMetadataSha256 = Hash('9') } : state).ToArray() },
            _ => value with { Databases = fixture.Create(2).Databases },
        });
        _ = await Assert.ThrowsAsync<DeltaExecutionException>(() => fixture.Append(value));
        Assert.DoesNotContain(fixture.Gateway.Names, name => name.Contains("/continuations/", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ReplaySkippedOrdinalWrongChainAndRegressionFailClosed()
    {
        using var fixture = new Fixture();
        _ = await fixture.Reserve();
        SourceBackedLocalRepairContinuation first = await fixture.Append(fixture.Create(1));
        await Reject(() => fixture.Append(first), "delta_rollover_claim_conflict");
        await Reject(() => fixture.Append(fixture.Create(3, first)));
        await Reject(() => fixture.Append(fixture.Sign(fixture.Create(2, first) with { PreviousContinuationSha256 = Hash('9') })));
        SourceBackedLocalRepairContinuation second = await fixture.Append(fixture.Create(2, first));
        SourceBackedLocalRepairContinuation third = fixture.Create(3, second);
        await Reject(() => fixture.Append(fixture.Sign(third with { Databases = first.Databases })));
        await Reject(() => fixture.Append(fixture.Sign(third with
        {
            Databases = third.Databases.Select((state, index) => index == 0 ? state with { RepairMarkerSha256 = Hash('9') } : state).ToArray(),
        })));
    }

    [Fact]
    public async Task ExpiredForgedUntrustedOrAliasedSignerCannotPublish()
    {
        using var fixture = new Fixture();
        _ = await fixture.Reserve();
        SourceBackedLocalRepairContinuation value = fixture.Create(1);
        await Reject(() => fixture.Append(value, fixture.Now.AddMinutes(10)));
        await Reject(() => fixture.Append(value with { AttestationSignature = "not-base64" }));
        await Reject(() => fixture.Append(value with { AttestationSignature = Convert.ToBase64String(new byte[64]) }));
        await Reject(() => fixture.Append(fixture.Sign(value with { ExpiresAtUtc = fixture.Now.AddMinutes(16) })));
        await Reject(() => fixture.Append(fixture.Sign(value with { IssuedAtUtc = fixture.Now.AddSeconds(1) })));
        SourceBackedLocalRepairContinuation alias = value with { AttestationKeyId = fixture.Authorization.AttestationKeyId };
        alias = alias with { AttestationSignature = Convert.ToBase64String(fixture.AuthorizationSigner.Sign(SourceBackedLocalRepairContinuationStore.Payload(alias))) };
        await Reject(() => fixture.Append(alias));
        var store = fixture.Store(fixture.AuthorizationSigner.PublicKeyFingerprintSha256);
        await Reject(() => store.AppendAsync(value, fixture.Authorization, value.Databases, fixture.Now, CancellationToken.None));
        PairedLocalTransitionAuthorization wrongAuth = fixture.Authorization with { DisposableReconciliationSha256 = Hash('1') };
        wrongAuth = wrongAuth with { AttestationSignature = Convert.ToBase64String(fixture.AuthorizationSigner.Sign(PairedLocalTransitionAuthorizationCanonicalizer.CreatePayload(wrongAuth))) };
        await Reject(() => fixture.ContinuationStore.AppendAsync(value, wrongAuth, value.Databases, fixture.Now, CancellationToken.None));
        Assert.DoesNotContain(fixture.Gateway.Names, name => name.Contains("/continuations/", StringComparison.Ordinal));
    }

    [Fact]
    public async Task IndependentObservedStateMustMatchSignedState()
    {
        using var fixture = new Fixture();
        _ = await fixture.Reserve();
        SourceBackedLocalRepairContinuation value = fixture.Create(1);
        await Reject(() => fixture.ContinuationStore.AppendAsync(value, fixture.Authorization, [], fixture.Now, CancellationToken.None));
    }

    [Fact]
    public async Task CallerMutationDuringClaimReadCannotChangeValidatedPublication()
    {
        using var fixture = new Fixture();
        _ = await fixture.Reserve();
        SourceBackedLocalRepairContinuation value = fixture.Create(1);
        string expected = JsonSerializer.Serialize(value);
        fixture.Gateway.BlockActiveRead = true;
        Task<SourceBackedLocalRepairContinuation> publication = fixture.Append(value);
        await fixture.Gateway.ReadEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        SourceBackedLocalRepairState[] states = Assert.IsType<SourceBackedLocalRepairState[]>(value.Databases);
        states[0] = states[0] with { PriorMetadataSha256 = Hash('9') };
        _ = fixture.Gateway.ReleaseRead.TrySetResult();
        Assert.Equal(expected, JsonSerializer.Serialize(await publication));
    }

    [Fact]
    public async Task ConcurrentCreateAtSameOrdinalHasOneWinner()
    {
        using var fixture = new Fixture();
        _ = await fixture.Reserve();
        fixture.Gateway.Compete = true;
        SourceBackedLocalRepairContinuation first = fixture.Create(1);
        SourceBackedLocalRepairContinuation second = fixture.Sign(first with { ExpiresAtUtc = fixture.Now.AddMinutes(4) });
        Exception?[] results = await Task.WhenAll(Attempt(fixture.Append(first)), Attempt(fixture.Append(second)));
        Assert.Equal(2, fixture.Gateway.Arrivals);
        _ = Assert.Single(results, item => item is null);
        Assert.Equal("delta_rollover_claim_conflict", Assert.IsType<DeltaExecutionException>(Assert.Single(results, item => item is not null)).Code);
        _ = Assert.Single(fixture.Gateway.Names, name => name.Contains("/continuations/", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("content")]
    [InlineData("generation")]
    [InlineData("retention")]
    [InlineData("policy")]
    public async Task RetainedReadbackAndPolicyAreAuthenticated(string fault)
    {
        using var fixture = new Fixture();
        _ = await fixture.Reserve();
        fixture.Gateway.Fault = fault;
        await Reject(() => fixture.Append(fixture.Create(1)), fault == "policy" ? "delta_source_repair_claim_policy_invalid" : "delta_source_repair_continuation_invalid");
    }

    [Fact]
    public async Task CurrentReadAuthenticatesEveryPriorSignedObject()
    {
        using var fixture = new Fixture();
        _ = await fixture.Reserve();
        SourceBackedLocalRepairContinuation first = await fixture.Append(fixture.Create(1));
        _ = await fixture.Append(fixture.Create(2, first));
        fixture.Gateway.CorruptFirst();
        await Reject(() => fixture.ContinuationStore.ReadAsync(fixture.Claim.ClaimId, fixture.Claim.AdmissionSha256, 2, fixture.Authorization, fixture.Now, CancellationToken.None));
    }

    private static async Task<Exception?> Attempt(Task task)
    {
        try { await task; return null; }
        catch (Exception exception) { return exception; }
    }

    private static async Task Reject(Func<Task> action, string expected = "delta_source_repair_continuation_invalid")
    {
        Assert.Equal(expected, (await Assert.ThrowsAsync<DeltaExecutionException>(action)).Code);
    }

    private static string Hash(char value)
    {
        return new(value, 64);
    }

    private sealed class Fixture : IDisposable
    {
        private readonly ECDsa _authorizationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa _evidenceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly P256MigrationEvidenceSigner _evidenceSigner;
        internal P256MigrationEvidenceSigner AuthorizationSigner { get; }
        internal DateTimeOffset Now { get; } = new(2026, 10, 2, 0, 0, 0, TimeSpan.Zero);
        internal Gateway Gateway { get; }
        internal SourceBackedLocalRepairClaim Claim { get; }
        internal PairedLocalTransitionAuthorization Authorization { get; }
        internal SourceBackedLocalRepairContinuationStore ContinuationStore { get; }
        private ReceiptAttestationTrustStore Trust { get; }
        private SourceBackedLocalRepairClaimStore Claims { get; }

        internal Fixture()
        {
            Gateway = new(Now);
            Claims = new(Gateway);
            AuthorizationSigner = new("authorization", _authorizationKey.ExportECPrivateKeyPem());
            _evidenceSigner = new("evidence", _evidenceKey.ExportECPrivateKeyPem());
            Trust = new([new(AuthorizationSigner.KeyId, AuthorizationSigner.ExportSubjectPublicKeyInfo()), new(_evidenceSigner.KeyId, _evidenceSigner.ExportSubjectPublicKeyInfo())]);
            Claim = new("1.0", Guid.NewGuid(), Hash('1'), Hash('2'), Hash('3'), Hash('4'),
                $"docker:{Hash('a')}:1700000000000:1700000001000:{Now.AddYears(-1).ToUnixTimeMilliseconds()}",
                "legacy-maliev-exact23-postgres-data", Now.AddYears(-1), Hash('5'),
                DatabaseInventory.ActiveDatabases.Select(database => new HistoricalLocalMetadataBinding(database, PairedLocalTransitionMetadataState.SettledPrior, Hash('6'))).ToArray(), Now, Now.AddDays(364));
            var auth = new PairedLocalTransitionAuthorization("1.0", Guid.NewGuid(), Guid.NewGuid(), Claim.FuturePlanSha256, Hash('7'), Hash('8'), Hash('9'), Hash('a'),
                new(DeltaTargetAuthorityKind.LocalAspire, "aspire://legacy-postgres-main-local/persistent-target", Claim.SystemIdentifierSha256), Hash('b'), Now, Now.AddMinutes(10), AuthorizationSigner.KeyId, null);
            Authorization = auth with { AttestationSignature = Convert.ToBase64String(AuthorizationSigner.Sign(PairedLocalTransitionAuthorizationCanonicalizer.CreatePayload(auth))) };
            ContinuationStore = Store();
        }

        internal SourceBackedLocalRepairContinuationStore Store(string? evidenceFingerprint = null)
        {
            return new(Gateway, Claims, Trust, AuthorizationSigner.PublicKeyFingerprintSha256, evidenceFingerprint ?? _evidenceSigner.PublicKeyFingerprintSha256);
        }

        internal Task<SourceBackedLocalRepairClaim> Reserve()
        {
            return Claims.ReserveAsync(Claim, Now, CancellationToken.None);
        }

        internal Task<SourceBackedLocalRepairContinuation> Append(SourceBackedLocalRepairContinuation value, DateTimeOffset? now = null)
        {
            return ContinuationStore.AppendAsync(value, Authorization, value.Databases, now ?? Now, CancellationToken.None);
        }

        internal SourceBackedLocalRepairContinuation Create(int ordinal, SourceBackedLocalRepairContinuation? previous = null)
        {
            var states = DatabaseInventory.ActiveDatabases.Select((database, index) => new SourceBackedLocalRepairState(database,
                index < ordinal - 1 ? SourceBackedLocalRepairPhase.Applied : SourceBackedLocalRepairPhase.Prior,
                Hash('6'), index < ordinal - 1 ? Hash('c') : null, index < ordinal - 1 ? Hash('d') : null, index < ordinal - 1 ? Hash('e') : null)).ToArray();
            return Sign(new("1.0", Claim.ClaimId, Claim.AdmissionSha256, Claim.PreimageSha256, Claim.SourceCaptureSha256, Claim.FuturePlanSha256, Claim.TargetGeneration,
                Authorization.AuthorizationId, SourceBackedLocalRepairContinuationStore.AuthorizationHash(Authorization), ordinal, previous is null ? null : SourceBackedLocalRepairContinuationStore.ComputeSha256(previous), states, Now, Now.AddMinutes(5), _evidenceSigner.KeyId, null));
        }

        internal SourceBackedLocalRepairContinuation Sign(SourceBackedLocalRepairContinuation value)
        {
            return value with { AttestationSignature = Convert.ToBase64String(_evidenceSigner.Sign(SourceBackedLocalRepairContinuationStore.Payload(value))) };
        }

        public void Dispose()
        {
            AuthorizationSigner.Dispose(); _evidenceSigner.Dispose(); _authorizationKey.Dispose(); _evidenceKey.Dispose();
        }
    }

    private sealed class Gateway(DateTimeOffset now) : IRolloverClaimObjectGateway
    {
        private readonly ConcurrentDictionary<string, RolloverClaimObject> _objects = new(StringComparer.Ordinal);
        private readonly TaskCompletionSource _barrier = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private long _generation;
        private int _arrivals;
        internal bool Compete { get; set; }
        internal string? Fault { get; set; }
        internal bool BlockActiveRead { get; set; }
        internal TaskCompletionSource ReadEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource ReleaseRead { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal int Arrivals => Volatile.Read(ref _arrivals);
        internal string[] Names => [.. _objects.Keys];
        public Task<RolloverClaimBucketPolicy> ReadPolicyAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(new RolloverClaimBucketPolicy(Fault != "policy", 31557600, true, false));
        }

        public async Task<RolloverClaimObject?> ReadAsync(string name, CancellationToken cancellationToken)
        {
            if (BlockActiveRead && name.Contains("/active/", StringComparison.Ordinal))
            {
                _ = ReadEntered.TrySetResult();
                await ReleaseRead.Task.WaitAsync(TimeSpan.FromSeconds(5), cancellationToken);
                BlockActiveRead = false;
            }
            _ = _objects.TryGetValue(name, out RolloverClaimObject? value);
            if (value is not null && name.Contains("/continuations/", StringComparison.Ordinal))
            {
                value = Fault switch
                {
                    "content" => value with { Content = "{}"u8.ToArray() },
                    "generation" => value with { Generation = value.Generation + 100 },
                    "retention" => value with { RetentionExpiresAtUtc = now.AddMinutes(1) },
                    _ => value,
                };
            }
            return value;
        }

        public async Task<RolloverClaimObject> CreateOnlyAsync(string name, byte[] content, CancellationToken cancellationToken)
        {
            if (Compete && name.Contains("/continuations/", StringComparison.Ordinal))
            {
                if (Interlocked.Increment(ref _arrivals) == 2) { _ = _barrier.TrySetResult(); }
                await _barrier.Task.WaitAsync(TimeSpan.FromSeconds(5), cancellationToken);
            }
            var value = new RolloverClaimObject(Interlocked.Increment(ref _generation), now, now.AddDays(366), [.. content]);
            return _objects.TryAdd(name, value) ? value : throw new DeltaExecutionException("delta_rollover_claim_conflict", "Already created.");
        }

        internal void CorruptFirst()
        {
            string name = Names.Single(name => name.EndsWith("/01", StringComparison.Ordinal));
            SourceBackedLocalRepairContinuation value = JsonSerializer.Deserialize<SourceBackedLocalRepairContinuation>(_objects[name].Content)!;
            _objects[name] = _objects[name] with { Content = JsonSerializer.SerializeToUtf8Bytes(value with { SourceCaptureSha256 = Hash('9') }) };
        }
    }
}

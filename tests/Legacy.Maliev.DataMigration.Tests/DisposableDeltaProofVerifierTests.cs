using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class DisposableDeltaProofVerifierTests : IDisposable
{
    private readonly ECDsa _planKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _localPlanKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _evidenceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _authorizationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    [Fact]
    public async Task Fresh_signed_disposable_reconciliation_admits_distinct_local_target()
    {
        Fixture fixture = await CreateAsync();

        Assert.True(DeltaSynchronizationPlanVerifier.Verify(fixture.ProofPlan, fixture.Trust, fixture.Now));
        Assert.True(DeltaSynchronizationPlanVerifier.Verify(fixture.LocalPlan, fixture.Trust, fixture.Now));
        Assert.True(Exact23DeltaReconciliationCoordinator.Verify(fixture.ProofResult, fixture.Trust));
        Assert.Equal(fixture.ProofPlan.SchemaPlanSha256, SchemaPlanCanonicalizer.ComputeSha256(fixture.Schema));

        DisposableDeltaProofVerifier.Verify(fixture.ProofPlan, fixture.ProofResult,
            fixture.LocalPlan, fixture.Schema, fixture.Trust, fixture.Now);
    }

    [Fact]
    public async Task Rejects_same_target_or_tampered_reconciliation()
    {
        Fixture fixture = await CreateAsync();

        Assert.Equal("delta_disposable_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            DisposableDeltaProofVerifier.Verify(fixture.ProofPlan, fixture.ProofResult,
                fixture.ProofPlan, fixture.Schema, fixture.Trust, fixture.Now)).Code);
        Assert.Equal("delta_disposable_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            DisposableDeltaProofVerifier.Verify(fixture.ProofPlan,
                fixture.ProofResult with { PlanSha256 = Hash('9') }, fixture.LocalPlan,
                fixture.Schema, fixture.Trust, fixture.Now)).Code);
    }

    [Fact]
    public async Task Rejects_expired_proof_and_changed_source_observation()
    {
        Fixture fixture = await CreateAsync();

        Assert.Equal("delta_disposable_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            DisposableDeltaProofVerifier.Verify(fixture.ProofPlan, fixture.ProofResult,
                fixture.LocalPlan, fixture.Schema, fixture.Trust, fixture.Now.AddHours(13))).Code);
        Assert.Equal("delta_disposable_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            DisposableDeltaProofVerifier.Verify(fixture.ProofPlan, fixture.ProofResult,
                fixture.LocalPlan with { SourceObservationSha256 = Hash('9') },
                fixture.Schema, fixture.Trust, fixture.Now)).Code);
    }

    [Fact]
    public async Task Rejects_new_rows_after_disposable_proof()
    {
        Fixture fixture = await CreateAsync(changedLocalOperations: true);

        Assert.Equal("delta_disposable_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            DisposableDeltaProofVerifier.Verify(fixture.ProofPlan, fixture.ProofResult,
                fixture.LocalPlan, fixture.Schema, fixture.Trust, fixture.Now)).Code);
    }

    [Fact]
    public async Task Captured_proof_requires_identical_full_source_evidence_not_only_matching_operations()
    {
        Fixture matching = await CreateAsync(captured: true);
        DisposableDeltaProofVerifier.Verify(matching.ProofPlan, matching.ProofResult,
            matching.LocalPlan, matching.Schema, matching.Trust, matching.Now);

        Fixture drifted = await CreateAsync(captured: true, changedLocalEvidence: true);
        DeltaExecutionException failure = Assert.Throws<DeltaExecutionException>(() =>
            DisposableDeltaProofVerifier.Verify(drifted.ProofPlan, drifted.ProofResult,
                drifted.LocalPlan, drifted.Schema, drifted.Trust, drifted.Now));
        Assert.Equal("delta_disposable_proof_invalid", failure.Code);
    }

    [Fact]
    public async Task Captured_proof_rejects_a_separate_archive_even_with_identical_operations_and_source_evidence()
    {
        Fixture separate = await CreateAsync(captured: true, changedLocalArchive: true);
        Assert.True(DeltaSynchronizationPlanVerifier.Verify(separate.LocalPlan, separate.Trust, separate.Now));

        Assert.Equal("delta_paired_plan_publication_invalid", Assert.Throws<DeltaPlanException>(() =>
            PairedCapturedDeltaPlanPublicationGate.Verify(
                new(separate.ProofPlan, separate.LocalPlan), separate.Schema,
                separate.Trust, separate.Now)).Code);

        DeltaExecutionException failure = Assert.Throws<DeltaExecutionException>(() =>
            DisposableDeltaProofVerifier.Verify(separate.ProofPlan, separate.ProofResult,
                separate.LocalPlan, separate.Schema, separate.Trust, separate.Now));
        Assert.Equal("delta_disposable_proof_invalid", failure.Code);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task Captured_proof_rejects_a_changed_key_or_database_cutoff(
        bool changedKey, bool changedWindow)
    {
        Fixture fixture = await CreateAsync(captured: true,
            changedLocalCaptureKey: changedKey, changedLocalCaptureWindow: changedWindow);
        Assert.True(DeltaSynchronizationPlanVerifier.Verify(fixture.LocalPlan, fixture.Trust, fixture.Now));

        Assert.Equal("delta_disposable_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            DisposableDeltaProofVerifier.Verify(fixture.ProofPlan, fixture.ProofResult,
                fixture.LocalPlan, fixture.Schema, fixture.Trust, fixture.Now)).Code);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Reviewed_quotation_disposition_admits_signed_target_inventory(bool captured)
    {
        Fixture fixture = await CreateAsync(captured: captured, quotationDisposition: true);
        Assert.Equal(captured ? "1.3" : "1.2", fixture.ProofPlan.SchemaVersion);
        Assert.Equal(["legacy_compatibility.GoogleAnalyticsOutbox", "public.QuotationAcceptedOutcome"],
            fixture.ProofPlan.Databases.Single(database => database.Database == "Quotation")
                .Tables.Select(table => table.Table));
        Assert.True(DeltaSynchronizationPlanVerifier.Verify(fixture.ProofPlan, fixture.Trust, fixture.Now));
        Assert.True(Exact23DeltaReconciliationCoordinator.Verify(fixture.ProofResult, fixture.Trust));

        DisposableDeltaProofVerifier.Verify(fixture.ProofPlan, fixture.ProofResult,
            fixture.LocalPlan, fixture.Schema, fixture.Trust, fixture.Now);
    }

    [Fact]
    public async Task Reviewed_quotation_disposition_rejects_signed_unexpected_local_target()
    {
        Fixture fixture = await CreateAsync(quotationDisposition: true, changedLocalTableInventory: true);
        Assert.True(DeltaSynchronizationPlanVerifier.Verify(fixture.LocalPlan, fixture.Trust, fixture.Now));

        Assert.Equal("delta_disposable_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            DisposableDeltaProofVerifier.Verify(fixture.ProofPlan, fixture.ProofResult,
                fixture.LocalPlan, fixture.Schema, fixture.Trust, fixture.Now)).Code);
    }

    [Fact]
    public async Task Zero_delete_validator_admits_signed_same_capture_and_distinct_target()
    {
        Fixture fixture = await CreateAsync(captured: true, quotationDisposition: true,
            matchingInsertOperations: true);
        Assert.Contains(fixture.ProofPlan.Databases.SelectMany(database => database.Tables),
            table => table.InsertCount == 1);
        PairedCapturedDeltaPlanPublicationGate.Verify(
            new(fixture.ProofPlan, fixture.LocalPlan), fixture.Schema, fixture.Trust, fixture.Now);

        ZeroDeleteCapturedDeltaProofValidator.Verify(fixture.ProofPlan, fixture.ProofResult,
            fixture.LocalPlan, fixture.Schema, fixture.Trust, fixture.Now);
    }

    [Fact]
    public async Task Zero_delete_validator_rejects_uncaptured_pair()
    {
        Fixture fixture = await CreateAsync();

        Assert.Equal("delta_zero_delete_captured_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            ZeroDeleteCapturedDeltaProofValidator.Verify(fixture.ProofPlan, fixture.ProofResult,
                fixture.LocalPlan, fixture.Schema, fixture.Trust, fixture.Now)).Code);
    }

    [Fact]
    public async Task Zero_delete_validator_rejects_tampered_or_stale_proof()
    {
        Fixture fixture = await CreateAsync(captured: true);

        Assert.Equal("delta_disposable_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            ZeroDeleteCapturedDeltaProofValidator.Verify(fixture.ProofPlan,
                fixture.ProofResult with { PlanSha256 = Hash('9') }, fixture.LocalPlan,
                fixture.Schema, fixture.Trust, fixture.Now)).Code);
        Assert.Equal("delta_disposable_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            ZeroDeleteCapturedDeltaProofValidator.Verify(fixture.ProofPlan, fixture.ProofResult,
                fixture.LocalPlan, fixture.Schema, fixture.Trust, fixture.Now.AddHours(13))).Code);
    }

    [Fact]
    public async Task Zero_delete_validator_rejects_a_signed_matched_delete()
    {
        Fixture fixture = await CreateAsync(captured: true, deleteOperations: true);
        Assert.True(DeltaSynchronizationPlanVerifier.Verify(fixture.ProofPlan, fixture.Trust, fixture.Now));
        Assert.True(DeltaSynchronizationPlanVerifier.Verify(fixture.LocalPlan, fixture.Trust, fixture.Now));

        Assert.Equal("delta_zero_delete_captured_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            ZeroDeleteCapturedDeltaProofValidator.Verify(fixture.ProofPlan, fixture.ProofResult,
                fixture.LocalPlan, fixture.Schema, fixture.Trust, fixture.Now)).Code);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task Zero_delete_validator_rejects_changed_capture_or_operations(
        bool changedArchive, bool changedOperations)
    {
        Fixture fixture = await CreateAsync(captured: true,
            changedLocalArchive: changedArchive, changedLocalOperations: changedOperations);

        Assert.Equal("delta_disposable_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            ZeroDeleteCapturedDeltaProofValidator.Verify(fixture.ProofPlan, fixture.ProofResult,
                fixture.LocalPlan, fixture.Schema, fixture.Trust, fixture.Now)).Code);
    }

    [Fact]
    public async Task Signed_schema14_pair_accepts_later_disposable_proof_without_authorizing_local_execution()
    {
        Fixture fixture = await CreateAsync(pairedTransition: true, quotationDisposition: true,
            captured: true, matchingInsertOperations: true);
        Assert.True(fixture.ProofResult.ReconciledAtUtc > fixture.LocalPlan.CreatedAtUtc);
        Assert.Equal("1.4", fixture.LocalPlan.SchemaVersion);
        ZeroDeleteCapturedDeltaProofValidator.Verify(fixture.ProofPlan, fixture.ProofResult,
            fixture.LocalPlan, fixture.Schema, fixture.Trust, fixture.Now);

        Fixture changedCapture = await CreateAsync(pairedTransition: true, quotationDisposition: true,
            captured: true, matchingInsertOperations: true, changedLocalArchive: true);
        Assert.Equal("delta_disposable_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            ZeroDeleteCapturedDeltaProofValidator.Verify(changedCapture.ProofPlan,
                changedCapture.ProofResult, changedCapture.LocalPlan, changedCapture.Schema,
                changedCapture.Trust, changedCapture.Now)).Code);
        Fixture wrongHash = await CreateAsync(pairedTransition: true, quotationDisposition: true,
            captured: true, matchingInsertOperations: true, changedLocalTransitionHash: true);
        Assert.True(DeltaSynchronizationPlanVerifier.Verify(wrongHash.LocalPlan,
            wrongHash.Trust, wrongHash.Now));
        Assert.Equal("delta_disposable_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            ZeroDeleteCapturedDeltaProofValidator.Verify(wrongHash.ProofPlan,
                wrongHash.ProofResult, wrongHash.LocalPlan, wrongHash.Schema,
                wrongHash.Trust, wrongHash.Now)).Code);
        Fixture changedOperations = await CreateAsync(pairedTransition: true, quotationDisposition: true,
            captured: true, changedLocalOperations: true);
        Assert.Equal("delta_disposable_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            ZeroDeleteCapturedDeltaProofValidator.Verify(changedOperations.ProofPlan,
                changedOperations.ProofResult, changedOperations.LocalPlan,
                changedOperations.Schema, changedOperations.Trust, changedOperations.Now)).Code);
        Assert.Equal("delta_disposable_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            ZeroDeleteCapturedDeltaProofValidator.Verify(fixture.ProofPlan,
                fixture.ProofResult with { PlanSha256 = Hash('9') }, fixture.LocalPlan,
                fixture.Schema, fixture.Trust, fixture.Now)).Code);
        Assert.Equal("delta_disposable_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            ZeroDeleteCapturedDeltaProofValidator.Verify(fixture.ProofPlan, fixture.ProofResult,
                fixture.LocalPlan, fixture.Schema, fixture.Trust, fixture.Now.AddHours(13))).Code);
        Fixture deletes = await CreateAsync(pairedTransition: true, quotationDisposition: true,
            captured: true, deleteOperations: true);
        Assert.Equal("delta_disposable_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            ZeroDeleteCapturedDeltaProofValidator.Verify(deletes.ProofPlan, deletes.ProofResult,
                deletes.LocalPlan, deletes.Schema, deletes.Trust, deletes.Now)).Code);
    }

    [Fact]
    public async Task Local_transition_authorization_binds_exact_proof_and_target_but_cannot_enter_current_apply()
    {
        Fixture fixture = await CreateAsync(pairedTransition: true, quotationDisposition: true,
            captured: true, matchingInsertOperations: true);
        using var signer = new P256MigrationEvidenceSigner("local-transition-authorization",
            _authorizationKey.ExportECPrivateKeyPem());
        PairedCapturedDeltaPlans plans = new(fixture.ProofPlan, fixture.LocalPlan);
        DeltaTargetAuthority localAuthority = fixture.LocalPlan.TargetAuthority!;
        string physicalHash = fixture.LocalPlan.QuotationTransitionSchemaSha256!;
        PairedLocalTransitionAuthorization authorization =
            PairedLocalTransitionAuthorizationPolicy.Produce(plans, fixture.ProofResult,
                fixture.Schema, fixture.Trust, localAuthority,
                fixture.LocalPlan.TargetObservationSha256, physicalHash,
                fixture.Now.AddMinutes(-1), fixture.Now.AddMinutes(5), signer);

        void Verify(PairedLocalTransitionAuthorization candidate,
            PairedCapturedDeltaPlans? pair = null,
            Exact23DeltaReconciliationResult? result = null,
            DeltaTargetAuthority? authority = null,
            string? targetObservation = null,
            string? schemaHash = null,
            DateTimeOffset? now = null)
        {
            PairedLocalTransitionAuthorizationPolicy.Verify(candidate, pair ?? plans,
                result ?? fixture.ProofResult, fixture.Schema, fixture.Trust,
                authority ?? localAuthority,
                targetObservation ?? fixture.LocalPlan.TargetObservationSha256,
                schemaHash ?? physicalHash, now ?? fixture.Now);
        }

        Verify(authorization);
        Assert.Equal(DeltaSynchronizationPlanCanonicalizer.ComputeSha256(fixture.LocalPlan),
            authorization.PersistentPlanSha256);
        Assert.Equal(Exact23DeltaReconciliationCoordinator.ComputeSha256(fixture.ProofResult),
            authorization.DisposableReconciliationSha256);
        PairedLocalTransitionAuthorization wrongProofUnsigned = authorization with
        {
            DisposableReconciliationSha256 = Hash('f'),
            AttestationSignature = null,
        };
        PairedLocalTransitionAuthorization wrongProofSigned = wrongProofUnsigned with
        {
            AttestationSignature = Convert.ToBase64String(signer.Sign(
                PairedLocalTransitionAuthorizationCanonicalizer.CreatePayload(wrongProofUnsigned))),
        };
        Assert.Equal("delta_paired_local_transition_authorization_invalid",
            Assert.Throws<DeltaExecutionException>(() => Verify(wrongProofSigned)).Code);
        using var localSigner = new P256MigrationEvidenceSigner("local-plan",
            _localPlanKey.ExportECPrivateKeyPem());
        DeltaSynchronizationPlan replayedUnsigned = fixture.LocalPlan with
        {
            PlanId = Guid.NewGuid(),
            AttestationSignature = null,
        };
        DeltaSynchronizationPlan replayedPlan = replayedUnsigned with
        {
            AttestationSignature = Convert.ToBase64String(localSigner.Sign(
                DeltaSynchronizationPlanCanonicalizer.CreatePayload(replayedUnsigned))),
        };
        Assert.True(DeltaSynchronizationPlanVerifier.Verify(replayedPlan,
            fixture.Trust, fixture.Now));
        Assert.Equal("delta_paired_local_transition_authorization_invalid",
            Assert.Throws<DeltaExecutionException>(() => Verify(authorization,
                pair: new(fixture.ProofPlan, replayedPlan))).Code);
        PairedLocalTransitionAuthorization earlyUnsigned = authorization with
        {
            IssuedAtUtc = fixture.ProofResult.ReconciledAtUtc.AddSeconds(-1),
            AttestationSignature = null,
        };
        PairedLocalTransitionAuthorization earlySigned = earlyUnsigned with
        {
            AttestationSignature = Convert.ToBase64String(signer.Sign(
                PairedLocalTransitionAuthorizationCanonicalizer.CreatePayload(earlyUnsigned))),
        };
        Assert.Equal("delta_paired_local_transition_authorization_invalid",
            Assert.Throws<DeltaExecutionException>(() => Verify(earlySigned)).Code);
        Assert.Equal("delta_paired_local_transition_authorization_invalid",
            Assert.Throws<DeltaExecutionException>(() => Verify(authorization,
                result: fixture.ProofResult with { PlanSha256 = Hash('f') })).Code);
        Assert.Equal("delta_paired_local_transition_authorization_invalid",
            Assert.Throws<DeltaExecutionException>(() => Verify(authorization,
                authority: localAuthority with { SystemIdentifierSha256 = Hash('f') })).Code);
        Assert.Equal("delta_paired_local_transition_authorization_invalid",
            Assert.Throws<DeltaExecutionException>(() => Verify(authorization,
                targetObservation: Hash('f'))).Code);
        Assert.Equal("delta_paired_local_transition_authorization_invalid",
            Assert.Throws<DeltaExecutionException>(() => Verify(authorization,
                schemaHash: Hash('f'))).Code);
        Assert.Equal("delta_paired_local_transition_authorization_invalid",
            Assert.Throws<DeltaExecutionException>(() => Verify(authorization,
                now: fixture.Now.AddMinutes(6))).Code);
        Assert.Equal("delta_paired_local_transition_authorization_invalid",
            Assert.Throws<DeltaExecutionException>(() => Verify(authorization,
                authority: new(DeltaTargetAuthorityKind.ProductionCloudNativePg,
                    "gke://maliev-website/production-test", Hash('f')))).Code);

        Assert.Equal("delta_execution_authorization_request_invalid",
            Assert.Throws<DeltaExecutionException>(() => DeltaExecutionAuthorizationProducer.Produce(
                fixture.LocalPlan, fixture.Now.AddMinutes(-1), fixture.Now.AddMinutes(5), signer)).Code);
        Assert.Equal("delta_quotation_transition_plan_invalid",
            Assert.Throws<DeltaPlanException>(() => QuotationDeltaPhysicalSchemaGuard.ExpectedPhysicalSchema(
                fixture.LocalPlan, fixture.Schema.Databases.Single(database => database.Database == "Quotation"))).Code);
        Assert.Equal("delta_quotation_transition_plan_invalid",
            (await Assert.ThrowsAsync<DeltaPlanException>(() =>
                new PostgreSqlDeltaMetadataProvisioner(new("Host=should-not-connect",
                    localAuthority)).ProvisionAsync(fixture.LocalPlan, fixture.Schema,
                    CancellationToken.None))).Code);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task Local_transition_authorization_refuses_signed_delete_or_wrong_transition_hash(
        bool plannedDeletes, bool wrongTransitionHash)
    {
        Fixture fixture = await CreateAsync(pairedTransition: true, quotationDisposition: true,
            captured: true, deleteOperations: plannedDeletes,
            matchingInsertOperations: !plannedDeletes,
            changedLocalTransitionHash: wrongTransitionHash);
        using var signer = new P256MigrationEvidenceSigner("local-transition-authorization",
            _authorizationKey.ExportECPrivateKeyPem());
        Assert.True(DeltaSynchronizationPlanVerifier.Verify(fixture.LocalPlan,
            fixture.Trust, fixture.Now));

        Assert.Equal("delta_paired_local_transition_authorization_invalid",
            Assert.Throws<DeltaExecutionException>(() =>
                PairedLocalTransitionAuthorizationPolicy.Produce(
                    new(fixture.ProofPlan, fixture.LocalPlan), fixture.ProofResult,
                    fixture.Schema, fixture.Trust, fixture.LocalPlan.TargetAuthority!,
                    fixture.LocalPlan.TargetObservationSha256,
                    fixture.LocalPlan.QuotationTransitionSchemaSha256!,
                    fixture.Now.AddMinutes(-1), fixture.Now.AddMinutes(5), signer)).Code);
    }

    [Fact]
    public async Task Local_transition_authorization_rejects_reused_disposable_evidence_key()
    {
        Fixture fixture = await CreateAsync(pairedTransition: true, quotationDisposition: true,
            captured: true, matchingInsertOperations: true,
            reuseProofEvidenceAsAuthorization: true);
        using var reusedSigner = new P256MigrationEvidenceSigner("proof-evidence",
            _evidenceKey.ExportECPrivateKeyPem());
        Assert.Equal("delta_paired_local_transition_authorization_invalid",
            Assert.Throws<DeltaExecutionException>(() =>
                PairedLocalTransitionAuthorizationPolicy.Produce(
                    new(fixture.ProofPlan, fixture.LocalPlan), fixture.ProofResult,
                    fixture.Schema, fixture.Trust, fixture.LocalPlan.TargetAuthority!,
                    fixture.LocalPlan.TargetObservationSha256,
                    fixture.LocalPlan.QuotationTransitionSchemaSha256!,
                    fixture.Now.AddMinutes(-1), fixture.Now.AddMinutes(5), reusedSigner)).Code);
    }

    private async Task<Fixture> CreateAsync(bool changedLocalOperations = false,
        bool captured = false, bool changedLocalEvidence = false, bool quotationDisposition = false,
        bool changedLocalTableInventory = false, bool changedLocalArchive = false,
        bool changedLocalCaptureKey = false, bool changedLocalCaptureWindow = false,
        bool deleteOperations = false, bool matchingInsertOperations = false,
        bool pairedTransition = false, bool changedLocalTransitionHash = false,
        bool reuseProofEvidenceAsAuthorization = false)
    {
        DateTimeOffset now = new(2026, 9, 25, 8, 0, 0, TimeSpan.Zero);
        TableCopyPlan[] quotationOutboxes =
        [
            ApprovedSourceDispositionManifestTests.Outbox(CurrentQuotationSourceContract.GoogleAnalyticsOutbox,
                "PK_GoogleAnalyticsOutbox", "UX_GoogleAnalyticsOutbox_EventKey", uniqueIndex: true),
            ApprovedSourceDispositionManifestTests.Outbox(CurrentQuotationSourceContract.QuotationOutcomeOutbox,
                "PK_QuotationOutcomeOutbox", "UQ_QuotationOutcomeOutbox_EventKey", uniqueIndex: false),
        ];
        FreshSchemaPlan schema = new("2.0", now.AddMinutes(-10), new string('a', 40),
            [.. DatabaseInventory.ActiveDatabases.Select(name =>
            {
                bool disposed = quotationDisposition && name == "Quotation";
                var database = new DatabaseSchemaPlan(name, "1.0",
                Hash('a'), Hash('b'), disposed ? quotationOutboxes : [new TableCopyPlan("dbo", "items", "public", "items", ["id"], ["id"])
                {
                    ColumnTypes = new Dictionary<string, string> { ["id"] = "integer" },
                    PrimaryKey = new("pk_items", ["id"]),
                }])
                {
                    TargetExtensionProfile = ApprovedTargetExtensionManifest.ProfileForDatabase(name),
                    SourceDispositionProfile = disposed ? ApprovedSourceDispositionManifest.QuotationOutboxesV1 : null,
                    SourceTableDispositions = disposed
                        ? ApprovedSourceDispositionManifest.DispositionsForDatabase(name, quotationOutboxes) : [],
                };
                return disposed ? database with
                {
                    TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(database),
                } : database;
            })]);
        using var planSigner = new P256MigrationEvidenceSigner("proof-plan", _planKey.ExportECPrivateKeyPem());
        using var localPlanSigner = new P256MigrationEvidenceSigner("local-plan", _localPlanKey.ExportECPrivateKeyPem());
        using var evidenceSigner = new P256MigrationEvidenceSigner("proof-evidence", _evidenceKey.ExportECPrivateKeyPem());
        using var authorizationSigner = new P256MigrationEvidenceSigner("local-transition-authorization",
            _authorizationKey.ExportECPrivateKeyPem());
        var trust = new ReceiptAttestationTrustStore(
            [new(planSigner.KeyId, planSigner.ExportSubjectPublicKeyInfo()),
                new(localPlanSigner.KeyId, localPlanSigner.ExportSubjectPublicKeyInfo()),
                new(evidenceSigner.KeyId, evidenceSigner.ExportSubjectPublicKeyInfo()),
                new(authorizationSigner.KeyId, authorizationSigner.ExportSubjectPublicKeyInfo())]);
        DeltaSynchronizationPlan proofPlan = MakePlan("disposable-proof", Hash('1'), now.AddMinutes(-3),
            matchingInsertOperations);
        DeltaSynchronizationPlan localPlan = MakePlan("persistent-main", Hash('2'),
            now.AddMinutes(pairedTransition ? -3 : -1),
            changedLocalOperations || matchingInsertOperations, changedLocalTableInventory);
        var inspector = new Inspector(pairedTransition, schema);
        var coordinator = new Exact23DeltaReconciliationCoordinator(inspector, inspector,
            new Checkpoints(proofPlan, schema, pairedTransition),
            new FixedTime(now.AddMinutes(-2)), evidenceSigner);
        Exact23DeltaReconciliationResult result = await coordinator.ReconcileAsync(proofPlan, schema,
            CancellationToken.None);
        return new(proofPlan, result, localPlan, schema, trust, now);

        DeltaSynchronizationPlan MakePlan(string id, string systemHash, DateTimeOffset created,
            bool changedOperations = false, bool changedTableInventory = false)
        {
            CanonicalDeltaOperation[] changed = [new(
                deleteOperations ? DeltaOperationKind.Delete : DeltaOperationKind.Insert,
                Hash('e'), deleteOperations ? null : Hash('f'),
                deleteOperations ? Hash('f') : null)];
            DeltaDatabasePlan[] databases = [.. DatabaseInventory.ActiveDatabases.Select(name => new DeltaDatabasePlan(name,
                [.. new QuotationDeltaExecutionMapping(schema.Databases.Single(item => item.Database == name))
                    .TargetSchema.Tables.Select(table => new DeltaTablePlan(
                        changedTableInventory && name == "Quotation" && table.TargetTable == "QuotationAcceptedOutcome"
                            ? "public.QuotationOutcomeOutbox" : $"{table.TargetSchema}.{table.TargetTable}",
                        changedOperations && name == "ContactRequest" && !deleteOperations ? 1 : 0,
                        0, deleteOperations && name == "ContactRequest" ? 1 : 0,
                        changedOperations && name == "ContactRequest" ? 0 : 1,
                        DeltaSynchronizationPlanCanonicalizer.ComputeOperationsSha256(
                            (changedOperations || deleteOperations) && name == "ContactRequest" ? changed : []),
                        (changedOperations || deleteOperations) && name == "ContactRequest" ? changed : []))]))];
            var request = new DeltaPlanSigningRequest(schema.SourceCommitSha, now.AddMinutes(-5), Hash('3'),
                SchemaPlanCanonicalizer.ComputeSha256(schema), Hash('4'), "local-aspire",
                "legacy-postgres-main-local", "generation-1", Hash('5'), Hash('6'),
                reuseProofEvidenceAsAuthorization ? evidenceSigner.PublicKeyFingerprintSha256 :
                    authorizationSigner.PublicKeyFingerprintSha256,
                databases)
            {
                TargetAuthority = new(DeltaTargetAuthorityKind.LocalAspire,
                    $"aspire://legacy-postgres-main-local/{id}", systemHash),
                SourceMode = DeltaSourceMode.LiveReadOnly,
                SourceObservationSha256 = Hash('8'),
                SourceCaptureCompletedAtUtc = now.AddMinutes(-4),
                SourceCaptureManifest = captured ? new(Hash(changedLocalCaptureKey && id == "persistent-main" ? '9' : '0'),
                    [.. DatabaseInventory.ActiveDatabases.Select(name =>
                    {
                        DatabaseSchemaPlan databaseSchema = schema.Databases.Single(item => item.Database == name);
                        DeltaDatabasePlan databasePlan = databases.Single(item => item.Database == name);
                        DatabaseReconciliationEvidence evidence = new Inspector().InspectAsync(databaseSchema,
                            CancellationToken.None).GetAwaiter().GetResult();
                        if (changedLocalEvidence && id == "persistent-main" && name == "ContactRequest")
                        {
                            evidence = evidence with
                            {
                                Tables = [evidence.Tables[0] with { ContentSha256 = Hash('e') }],
                            };
                        }
                        return new DeltaDatabaseCaptureBinding(name,
                            now.AddMinutes(-4).AddSeconds(changedLocalCaptureWindow && id == "persistent-main" ? -29 : -30),
                            now.AddMinutes(-4).AddSeconds(-10), evidence,
                            [.. databasePlan.Tables.Select(tablePlan => new DeltaTableCaptureBinding(tablePlan.Table,
                                CaptureId(name + tablePlan.Table),
                                CaptureDigest(changedLocalArchive && id == "persistent-main" ? id : "shared", name + tablePlan.Table), Hash('a'),
                                tablePlan.InsertCount + tablePlan.UpdateCount, tablePlan.OperationsSha256))]);
                    })]) : null,
                QuotationTransitionSchemaSha256 = pairedTransition
                    ? changedLocalTransitionHash && id == "persistent-main" ? Hash('f') :
                        PostgreSqlSchemaFingerprint.ComputeQuotationBootstrapExpected(
                            schema.Databases.Single(item => item.Database == "Quotation"), true)
                    : null,
                PairedTransitionPlanOnly = pairedTransition && id == "persistent-main" ? true : null,
            };
            return DeltaSynchronizationPlanProducer.Produce(request,
                id.StartsWith("disposable-", StringComparison.Ordinal) ? planSigner : localPlanSigner, created);
        }
    }

    private static string CaptureDigest(string id, string database)
    {
        return Convert.ToHexString(SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(id + ":" + database))).ToLowerInvariant();
    }

    private static Guid CaptureId(string table)
    {
        byte[] digest = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(table));
        return new Guid(digest.AsSpan(0, 16));
    }

    private static string Hash(char value)
    {
        return new(value, 64);
    }

    public void Dispose()
    {
        _planKey.Dispose();
        _localPlanKey.Dispose();
        _evidenceKey.Dispose();
        _authorizationKey.Dispose();
    }

    private sealed record Fixture(DeltaSynchronizationPlan ProofPlan,
        Exact23DeltaReconciliationResult ProofResult, DeltaSynchronizationPlan LocalPlan,
        FreshSchemaPlan Schema, ReceiptAttestationTrustStore Trust, DateTimeOffset Now);

    private sealed class Inspector(bool pairedTransition = false, FreshSchemaPlan? fullSchema = null)
        : IDeltaReconciliationInspector
    {
        public Task<DatabaseReconciliationEvidence> InspectAsync(DatabaseSchemaPlan schema,
            CancellationToken cancellationToken)
        {
            TableReconciliationEvidence[] tables = [.. new QuotationDeltaExecutionMapping(schema).TargetSchema.Tables
                .Select(table => new TableReconciliationEvidence($"{table.TargetSchema}.{table.TargetTable}",
                    1, Hash('c'), Hash('d'), new Dictionary<string, long>(),
                    new Dictionary<string, long>()))];
            string physicalHash = pairedTransition && schema.Database == "Quotation"
                ? PostgreSqlSchemaFingerprint.ComputeQuotationBootstrapExpected(
                    fullSchema!.Databases.Single(item => item.Database == "Quotation"), true)
                : schema.TargetSchemaSha256;
            return Task.FromResult(new DatabaseReconciliationEvidence(schema.Database,
                schema.SourceSchemaSha256, physicalHash, tables)
            {
                TargetExtensionStateSha256 = schema.TargetExtensionProfile is null ? null : Hash('e'),
            });
        }
    }

    private sealed class Checkpoints(DeltaSynchronizationPlan plan, FreshSchemaPlan schema,
        bool pairedTransition = false)
        : IExact23DeltaCheckpointReader
    {
        public Task<IReadOnlyList<DeltaDatabaseCheckpointEvidence>> ReadAsync(
            DeltaSynchronizationPlan requestedPlan, FreshSchemaPlan schemaPlan,
            CancellationToken cancellationToken)
        {
            IReadOnlyList<DeltaDatabaseCheckpointEvidence> values =
                [.. DatabaseInventory.ActiveDatabases.Select(name =>
                {
                    DeltaDatabasePlan database = plan.Databases.Single(item => item.Database == name);
                    DatabaseSchemaPlan databaseSchema = schema.Databases.Single(item => item.Database == name);
                    DatabaseReconciliationEvidence evidence = new Inspector(pairedTransition, schema).InspectAsync(databaseSchema,
                        cancellationToken).GetAwaiter().GetResult();
                    return new DeltaDatabaseCheckpointEvidence(name, plan.PlanId,
                        DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan), plan.SourceCutoffUtc,
                        plan.TargetObservationSha256,
                        DeltaSynchronizationPlanCanonicalizer.ComputeDatabaseOperationsSha256(database),
                        DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(evidence),
                        plan.SourceCutoffUtc.AddMinutes(1));
                })];
            return Task.FromResult(values);
        }
    }

    private sealed class FixedTime(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow()
        {
            return now;
        }
    }
}

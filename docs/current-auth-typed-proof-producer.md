# Current Auth genuine typed proof producer: staged integration

This is source preparation only. Build, analyzers, formatting, focused tests, Windows process/job tests, native fixtures, proof assembly, and all closed Console cases are **UNRUN** for these staged bytes. Existing PR250 CI and component runs do not validate this source. No keys, processes, containers, volumes, database connections, or execution claims were created by this preparation. No repository commit applies.

Reference source: `work/current-auth-closure-20261012`, observed `ea03dc00c0f999c34f046bcf32754413119c2e33`; accepted main referenced by the owner was `2311152`. Integrate by hunks onto the owner's latest source, preserving its newer native fixture, Windows skip, custody, maintenance and reader fixes. A `.proposed` file is a reviewable full-file proposal, not authorization to replace unrelated newer changes.

## Mapping

New Core files go in `src/Legacy.Maliev.DataMigration/`:

- `CurrentAuthComponentBootstrapSubject.cs`
- `CurrentAuthNativeProofObserver.cs`

New Console files go in `src/Legacy.Maliev.DataMigration.Console/`:

- `CurrentAuthTypedProofArtifactImport.cs`
- `CurrentAuthTypedProofAssembler.cs`
- `CurrentAuthTypedProofConsole.cs`
- `CurrentAuthTypedHostJob.cs`
- `CurrentAuthTypedHostProducer.cs`

New tests go in `tests/Legacy.Maliev.DataMigration.Tests/`:

- `CurrentAuthExecutedProofRecorder.cs` (observation support, no signing or pass marker)
- `CurrentAuthComponentBootstrapSubjectTests.cs`
- `CurrentAuthTypedProofAssemblerTests.cs`
- `CurrentAuthTypedHostProducerTests.cs`

Existing-file proposals, with `.proposed` stripped:

| Proposal | Destination | Exact intended change |
|---|---|---|
| `CurrentAuthRepairAdmission.cs.proposed` | Core | Distinct enum `DisposableNativeComponent=2`, optional typed component subject, genuine definition-backed seed validation and separate signed claim domains. Future native/recovery/role hashes may be empty **only** in this explicit disposable component branch. Normal modes retain all hashes and fences. |
| `PostgreSqlCurrentAuthRepair.cs.proposed` | Core | One awaited read-only candidate observation after actual preservation validation and before Prepared publication. No connection, transaction or signing key enters the observer; atomic Start remains unchanged. |
| `CurrentAuthRepairConsole.cs.proposed` | Console | Reject component mode/subject before environment contact. No existing closed route can consume it. |
| `CurrentAuthRepairProofReadback.cs.proposed` | Console | Separate component-only readback entry, authentic per-case three distinct keys plus independent parent seed key, actual generated-schema provenance/source23 observation and actual anonymous target metadata. Ordinary readback requires eight real closed cases, including named disposable bootstrap. Preserve current scope, image/PGDATA/generation, receipts and removal chronology checks. |
| `CurrentAppOwnedRepairCustody.cs.proposed` | Console | Only optional `sharedReader=false` argument on streaming baseline read and its exact shared-read choice. Existing default stays exclusive; explicitly repeated held reads use FileShare.Read, denying writes/deletion. All canonical, owner/no-link, cap, lock and identity checks remain. |
| `CurrentAuthNativePreservationTests.cs.proposed` | Tests | Observe genuine seven existing definition cases: raw before/candidate, real rollback, commit plus separate-backend readback, exact SDK metadata, actual df384MiB, removal/absence/disposal and actual invocation return window. No full26 or accepted source-capture claim. |
| `CurrentAuthGuardedNativeExecutionTests.cs.proposed` | Tests | Observe six existing provider/failure cases, authentic actual case keys/claims/reservations/Prepared/commit/unknown/Stop/ack slots, full26 and inspected source23. Producer-enabled cases use the genuine distinct component seed/subject, actual run binding/native/target metadata, no fake future proof hashes. Old uninstrumented pure/component test seams are never assembled. |
| `CurrentAuthRepairProofReadbackTests.cs.proposed` | Tests | Ordinary named bootstrap now requires final-fleet; only explicit component entry has six cases. Preserve existing scope/chronology regressions. |
| `MigrationConsole.cs.proposed` | Console | Fixed routes `produce-current-auth-typed-host`, `run-current-auth-typed-testhost`, `assemble-current-auth-typed-proof`. |
| `ConsoleInvocation.cs.proposed` | Console | Same three exact route names in command allowlist. |

Move this document to an appropriate reviewed docs file during integration. `SHA256-MANIFEST.json` maps every frozen staged file to its destination and exact raw byte SHA256; the manifest excludes itself. No existing compiling worktree file was changed here.

## Genuine producer order and cycle separation

1. Root admits capacity, acquires a fresh actual Windows root binding, retains its external continuous budget/cleanup driver, supplies owner-only protected config, actual accepted source23 plan, intended disposable subject, three independent pinned public keys and the existing private signing material under custody. Root copies the complete accepted Release test bundle to that root; producer compares every copied file against the fixed canonical Release bundle and holds image bytes. Current Console/Core must equal copied test dependencies.
2. Run fixed `produce-current-auth-typed-host --config <protected definition config>` from the accepted frozen Console. It requires exact protected clean green source and actual owner13 before/after. The waiting child receives no test permission until assigned to a fresh named Windows job and admitted through its actual PID/start/nonce gate. Fixed `dotnet vstest` runs exactly seven definition cases. The producer observes actual parent/job RSS and host available memory every500ms, initial3GiB/floor1GiB/5GiB RSS, unchanged child512MiB GC, finite2h host and8min fixtures, bounded readers and immutable process frames. After actual host exit it independently inventories Docker and loopback ports and authenticates all case cleanup. Only then does it sign the genuine host record.
3. `assemble-current-auth-typed-proof` with phase `helper` authenticates actual TRX IDs/results/storage/codeBase, held executed images, actual case roots/bytes/native rollback/readback, host frames/capacity and cleanup. A separate case custody is resumed and artifacts are imported verbatim as immediate-root immutable files. Unsigned semantic readback precedes signing; signed readback reobserves identical held bytes. Actual owner13 and accepted source are checked before/after assembly. The helper subject excludes proof and operation digests, so replacing AuthHelperProofSHA with the produced hash does not change the subject.
4. Root supplies that **genuine** helper artifact/hash to the provider host config. The host authenticates the helper seven cases before signing a fresh component seed binding actual accepted source/owner/definition, executed images and parent root. This seed contains no own future native/recovery/role proof digests. Each provider case generates its actual independent three case keys, actual Windows custody, actual anonymous container/volume/native preimage and generated source23 physical observation. The generated schema is explicitly synthetic and is never represented as a fresh accepted source capture.
5. The fixed provider group runs the actual six provider/failure cases. Candidate data comes from the actual locked provider snapshot hook, never reconstructed from expected schema. Real return/exception is recorded before fixture cleanup; external VSTest exit is a separate later record. Prepared publication, real rollback, genuine committed/lost-ACK boundaries, retained unacknowledged slots, sticky Stop/replay and independent readback remain validated by the real provider and semantic reader.
6. Assemble `native`, `recovery`, and `maintenance` separately from the authentic provider host. Each domain has its own signed envelope and exact semantic readback. They are `provider-component` artifacts. Recovery is witnessed transactional rollback/unchanged-state evidence; it does not claim archive recovery, backup restore, EF-history copying or row deletion. A component artifact is never accepted by the ordinary closed Console reader.

## Custody and process details

Repeated immutable reads explicitly share READ only. Default exclusive custody behavior is unchanged. Flat imported bytes are copied with64KiB buffers, capped512MiB, independently hashed after durable flush/reopen and compared against original held identity/length/hash; no serializer changes signed bytes. Full baselines use the accepted bounded streaming/interning reader, not a byte-buffer allocation.

The Windows job is only an ownership observer. No KillTree, TerminateJobObject or kill-on-close is used. All member process identities and image handles are retained; cleanup individually verifies and terminates only those handles, continues cleaning other verified members after an individual failure, waits boundedly and proves empty job/exited processes/readers. A disallowed but verified job member retains its handle for cleanup. Unknown/unverifiable ownership fails closed and is recorded; it is never killed by PID/name alone.

The producer's signed memory journal covers the actual test job plus parent process, not unrelated Docker daemon/system services or the short fixed Git/GH/Docker utility processes. Their exact lifecycle observations are retained, but the root's continuous **total task** budget remains mandatory. The source does not call the job budget a complete total-resource proof.

## Remaining actual dependencies and limits

- Integrate these exact hunks/new files and inspect them; then Release zero-warning build, focused/new tests, affected suite, formatting/security/source-contract gates on the exact head. Source maps/pins that gate accepted source must include the new producer/reader/test dependency closure. Rebuild and freeze genuine current Console/Core/Test bundle; no stale component DLL can produce these typed artifacts.
- Execute Windows job/gate, cancellation/timeout/output-overflow/disallowed image/observer-failure/member-exit races and held-file replacement/sharing tests. New staging tests are pure negatives and do not substitute for actual process lifecycle tests. Job member enumeration is capped64; overflow/unknown ownership fails closed with remaining resource evidence rather than authorizing broad cleanup.
- Execute actual seven definition and six provider cases under unchanged capacity/CPU/memory/leases, authenticate real TRX and assemble/read back all four domains. Every native/check here is UNRUN. Verify repeated streaming readback under512MiB.
- Forced host termination can bypass fixture `finally`. This source emits no proof without independent actual absence and records owner/expiry on failure. Root's external driver must continue through failure and remove only exact verified run containers/anonymous volumes/proxies after durable ownership evidence, then prove absence. No successful exit/empty Windows job substitutes for container cleanup. The staged source does not implement a new Docker failure-cleanup authority.
- **Eight genuine closed Console cases remain a separate producer/integration requirement** before any real named disposable bootstrap or persistent permission. They must exercise actual closed review/authorize/verify/apply, complete fresh target-specific26/53 fleet, fresh accepted source23 physical plan, authentic claims/custody/maintenance and terminal chain. Six component fixtures cannot satisfy this requirement, and their distinct mode is rejected before closed environment contact. No closed producer or persistent execution acceptance is claimed here.
- Target-specific Auth EF histories remain untouched; current owner13 remains immutable. No Auth row archive/delete, history equality/copy, original operation continuation, issuer bypass or persistent target effect is added.

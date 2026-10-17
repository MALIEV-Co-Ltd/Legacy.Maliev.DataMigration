# Current Customer sequence definition preparation

This is pure preparation and disposable feasibility source. It grants no runtime, issuer, provider, Console, credential, production, or allocation-reset authority. No historical V1/V2/V3 schema fingerprints or the source inventory of 23 databases / 100 tables change.

## Fixed source and owner inputs

The historical source report `outputs/source-catalog-readonly-20261013-49878256c7fc465589c6f1d9a9a40b1f/report.json` has SHA256 `544b5f281078ff5fdc57120059d005f10bc5a6f1276d6ba2133be06569199581`. It reported SQL Server Customer.ID seed 1000, increment 1, current 69831. That report hash and allocation are historical provenance, never mandatory replay pins or instructions to reset another target's allocation. Preparation requires seed 1000 / increment 1, a fresh observation with current value in 999..2147483647, the same independently accepted current migration source SHA, and a supplied current report SHA256 equal to an independently accepted current report SHA256 argument with exact lowercase hash shape. A future caller must genuinely establish those independent inputs and actual source observations. Matching supplied arguments does not authenticate source observations, and a report hash alone does not prove target values.

Customer owner head: `e8493c35ca02e1ad0b35acf17d57c64640d263d8`, clean at inspection. Context SHA256: `6e5d93ba8d385099b0d06d782db17344fe9656fc056ddeed1c00c2f07710b970`. Model snapshot SHA256: `795475768f136faad32445b7eafa56d87ad6b98a58394292329b4534e450a7be`. The model uses integer identity by default; the requested 1000 definition comes from the independently observed source seed, not a fabricated EF annotation. Neither owner input nor this preparation digest authorizes execution.

## Exact candidate and native delta

The only candidate statement is `ALTER SEQUENCE public."Customer_ID_seq" START WITH 1000;`. It contains no RESTART, setval, row backfill, deletion, or journal adoption.

PostgreSQL 18 marks START as requiring a sequence rewrite and creates a new storage file in AlterSequence. Thus a seqstart-only raw catalog allowance would be false. See [PostgreSQL 18 sequence.c](https://github.com/postgres/postgres/blob/REL_18_STABLE/src/backend/commands/sequence.c), `init_params` START handling and `AlterSequence` / `RelationSetNewRelfilenumber`.

The explicit preparation compares only two bound tuples differently: the same sequence OID's pg_sequence.seqstart changes 1 to 1000, and that OID's pg_class.relfilenode changes to a different nonzero value. Independent native hashes retain every other field of both complete tuples. All other raw catalog facts (including occurrence keys), relation counts/digests, private journals, and every sequence physical tuple remain exact. Table/column/sequence identity, dependency, owner, increment, min/max, cache/cycle, last_value, is_called, and log_cnt remain exact. Already-start-1000 and other partial/unexpected states fail; there is no replay path.

The pure checker cannot authenticate an arbitrary supplied normalized tuple hash. Future native capture must derive both full and single-field-excluded hashes from the same genuine transaction, bind the target owner's independently observed identity, establish zero concurrent allocators and complete fleet maintenance, and retain authenticated complete baseline evidence. No catalog family is omitted or broadly allowed to change.

## Unrun validation and acceptance obligations

No build, test, database, or Docker execution was performed during source preparation. Required next checks: Release zero warnings/errors; focused pure tests and affected suite; formatter/analyzers; admitted serialized disposable PostgreSQL 18.4 native cases (allocated/unallocated, source-like and high values). Fixtures disable autovacuum only at disposable startup and positively observe the setting. They cap PostgreSQL at 512 MiB / 0.75 CPU, publish only loopback, use finite test cancellation, and own disposal on all paths. A proof driver must record exact container identity/labels, verify exit/removal after disposal, and record any cleanup failure before claiming acceptance.

Native tests must demonstrate transactional rollback restores the original relfilenode and complete snapshot, then commit and a separate read-only backend prove precisely the two proposed catalog deltas and unchanged allocation. If another raw field changes, this contract must reject and the evidence requires independent review; do not mask that field or relax catalog families. The source contract and fixtures are preparation, not accepted native proof, complete fleet reconciliation, or persistent permission.

The source-like allocated 69831 case and allocated high-value case establish physical state with genuine nextval after fixture-only setval and explicitly require the observed preimage log_cnt to be nonzero. Existing rollback, commit, and independent readback comparisons retain that exact count and every sequence physical tuple field. PostgreSQL 18 [sequence.c lines 449–483 and 1419–1423](https://raw.githubusercontent.com/postgres/postgres/REL_18_STABLE/src/backend/commands/sequence.c) copies the physical tuple for START and changes the start definition without resetting log_cnt. This source evidence motivates the test; the test remains unrun and adds no allowance to the core contract.

## October 16 continuation

The earlier preparation observations and unrun statements above are historical.
The approved current CustomerService head is now `f845b030dc74a179fe0f5021183828fa045775bc`.
Independent inspection and Root readback confirmed a clean checkout and identical
context and model snapshot bytes at both this head and the earlier `e8493c35` pin:
context SHA256 `6e5d93ba8d385099b0d06d782db17344fe9656fc056ddeed1c00c2f07710b970`;
snapshot SHA256 `795475768f136faad32445b7eafa56d87ad6b98a58394292329b4534e450a7be`.
The entire Data directory is unchanged; the intervening commit addresses optional
contact compatibility at the MVC boundary. Refresh the exact head pin while
retaining both model hashes and rejecting the old head on a fresh observation.
Historical receipts and their payload domains remain unchanged. New observations,
definitions, plans and authorizations are required; no old receipt is replay authority.

Reviewed production inventory is exactly 49 non-template databases and all 51
catalog entries, separately from local 26. Current source brackets full fleet
captures with independent read-only system-bound catalog observations. Release
build and 299 focused tests passed before this final owner-head update; the
updated tree must be rebuilt and retested. Genuine 18.1 component execution,
typed production proof consumption, full closed Console proofs and persistent
repair/data parity remain incomplete. The component pipeline is preparation and
grants no production authority.

The final October 16 candidate passed Release build with zero warnings/errors,
300 focused tests, all 14 disposable PostgreSQL 18.4 definition cases, and full
Core, Console and Tests formatting/analyzer verification at info severity.
The first broad native attempt failed while reading generated assembly files
whose ACLs did not satisfy owner-only custody. Restricting only the three generated
DLLs (bytes unchanged) resolved the setup failure; all 14 cases then passed.
Independent Docker inventories confirm all 29 disposable container/volume pairs
from the single owner check and both broad attempts are absent.

These checks do not establish genuine PostgreSQL 18.1 component execution, the
full Windows closed-proof suite, a typed production proof bridge, target repair,
fresh source migration, or local/production data parity. Full protected-head
hosted validation and required reviews remain mandatory before any merge.
The genuine production 18.1 image is now preloaded and all four full layer diffIDs
and actual UID 26/GID 102 were verified independently; an image preload is not a
component test or database proof. No persistent target was altered by this slice.

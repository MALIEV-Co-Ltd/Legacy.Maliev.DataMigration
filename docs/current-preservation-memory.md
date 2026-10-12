# Bounded preservation baseline serialization

Full preservation baselines retain every catalog tuple, relation row digest and sequence tuple, in the original order and multiplicity. Exact immutable records may share an instance across databases. No catalog family is omitted or normalized.

Default System.Text.Json serialization is unchanged. Hashing streams those exact bytes to SHA-256; the baseline reader uses a 32 KiB token buffer and exact record pooling. The owner-held input handle remains locked and identity checked. Output is create-new, bounded before forwarding bytes, disk flushed and read back through the same handle for an exact hash and identity comparison. Parse, capacity and cancellation failures return no partial baseline or execution acceptance.

Limits may only tighten: 512 MiB JSON, 256 databases, four million fact occurrences, 200,000 unique records, 4,096 UTF-8 bytes per string and 32 million retained unique string characters. These are resource bounds, not permission to truncate a baseline. Existing authorization, target, maintenance and preservation fences remain mandatory.

## Validation status before draft publication

Independent source review found no remaining blocker. Added regressions cover exact old serializer bytes/hashes; every fact field, order and multiplicity; 24-database exact pooling; chunked and escaped tokens; malformed/truncated JSON; limits; cancellation; owner-held input custody and create-new bounded output/readback.

The local full Release build was **not completed**: the unchanged runtime memory guard stopped it at 947,535,872 free bytes, below its 1 GiB floor. All exact owned workers exited and cleanup succeeded. Focused tests, relevant full suite and complete formatting are **not run** before this draft. The owner-approved 2026-10-10 validation-order exception applies; all unchanged hosted checks must pass on the exact proposed head before protected merge, and exact protected-main checks must pass afterward. No failed or skipped check is represented as passing.

The actual full 24-database closed-Console disposable proof under the unchanged 512 MiB child GC limit remains required after accepted-main publication. A source/component test is not persistent repair authority. Persistent database schema repairs and dual-target row parity are not established by this change.

## Local follow-up after draft creation

Capacity later admitted a complete Release build with zero warnings/errors. The first focused run had 16 passed and five failed assertions: four expected an exact JsonException rather than its JsonReaderException subclass, and one reversed a symmetric fixture without changing its order. Corrected tests preserve the rejection contract and now swap distinct occurrences. The post-format Release build passed with zero warnings/errors; all 21 focused tests passed, zero failed/skipped. Complete Core, Console and test project formatting passed; Core verify-no-changes passed. The relevant full suite remains not run locally: initial runtime memory-floor failure and the owner migration proof build required for that suite remains unprepared in this worktree. Exact-head hosted gates remain mandatory. No runtime/production acceptance is implied.

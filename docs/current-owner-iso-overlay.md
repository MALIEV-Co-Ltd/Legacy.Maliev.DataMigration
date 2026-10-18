# Current owner ISO literal-width preparation

This is pure preparation and disposable feasibility test source. It grants no database execution, maintenance, permit, archive/adoption, journal or persistent repair authority. Historical V1/V2/V3 manifests and the exact 23 database / 100 source table inventory remain unchanged.

The explicit `LiteralWidthV1` selection derives four physical consumption operands: Country.public.Country.ISO2/ISO3 and Material.public.Country.ISO2/ISO3, nullable character(2/3) to character varying(2/3). The selected physical view changes only those type fields. It never returns a fabricated historical signed source plan. Fresh exact source-plan and independently observed clean current owner pins are mandatory; these observations are caller inputs, not authenticated source acceptance.

Owner heads: CountryService `744b4747b1b6db1e106d1c19872043bc66bcad7a`; CatalogService `61a5cf8ccf5c0754c6a5ba3906c59517962e3fc3`. Six exact source file hashes are embedded in the contract. Catalog's current migration refuses nonempty consolidated Country. This test source does not bypass that owner migration.

## Literal preservation

The candidate is `rpad(column::text,width,' ')`. PostgreSQL's cast from bpchar to text removes trailing ASCII padding; restoring the exact fixed character width is a candidate for reproducing the original native bpchar field bytes. No arbitrary trim, case conversion, Unicode normalization, or copying from standalone Country is allowed. NULL remains NULL. Even an empty inserted literal has native fixed-width spaces; varchar retains those original physical spaces. Character width and UTF-8 byte length differ for Thai text.

The disposable PostgreSQL 18.4 tests compare `bpcharsend` before to `convert_to(varchar,'UTF8')` after, keyed by the existing ID, with null state included. Empty, all-space, padded, Thai, apostrophe, backslash, tab and combining-mark cases are synthetic. Country and Material fixtures use separate databases and independent values. A transaction rollback and committed readback are both required. The fixture checks outside rows, attributes, constraints, indices, defaults, dependency tuples, and sequence definition/state. It refuses partial types and index, expression index, CHECK, generated column and view dependencies before transition. The native fixture guard is test code only and is not a production dependency validator.

## Remaining integration and proof obligations

- No build, focused suite, formatter, or native proof has been run for this source preparation. Root owns admission and validation.
- Prove the candidate on native PostgreSQL with the immutable image before accepting literal-width behavior. Include direct byte lengths, bounded source inputs and every retained row; do not infer data preservation from schema hashes.
- Fresh independent complete target catalog and private actual-value snapshots must bind the exact target and source SHA. Preserve Material.Country's own before values; standalone Country is not its provenance.
- A future runtime must reject arbitrary dependencies, triggers, policies, partitions, unexpected catalog state and unknown collations, with complete fleet preservation. The pure TableCopyPlan check cannot observe native dependencies outside that model.
- Type rewrites may replace heap/index physical files. The fixture only compares stable catalog definitions and object identity. A production native transition contract must explicitly bind permitted physical replacements, all remaining raw catalog tuples, rows, and sequence state; no broad family masks.
- Independent owner default/timestamp/collation expectations remain significant. This overlay does not convert timestamps, change UTC defaults or collations, refresh target extension rows, repair Customer sequences, or imply current full-owner schema equality.
- The admitted complete Country preimage requires the production-observed UTC defaults. If fresh SQL V1 generation instead yields another default (including bare CURRENT_TIMESTAMP), preparation rejects it. A separately reviewed physical prerequisite default contract must resolve that boundary; this slice does not rewrite source fingerprints or tolerate the difference.
- Preserve the reviewed exact local 26 / production 49 non-template database keys, all 51 production catalog entries including template flags, and target-specific EF history. Independent system-bound inventory observations bracket each complete fleet capture. Missing, extra, substituted, case-changed and historical count-only inventories reject. No adoption or history fabrication is included.

Required validation: Release build with zero warnings/errors, focused pure tests, existing consumer selection/V1/V2/V3 regression suites, formatter/analyzers, then serialized disposable native proof under unchanged resource admission. Production writes remain outside this slice.

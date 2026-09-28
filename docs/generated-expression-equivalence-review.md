# Reviewed generated-expression precision casts (#185)

The 2026-09-28 exact-23 production catalog found seven generated-expression
facets whose PostgreSQL expressions omit intermediate casts in the source
schema plan. They use three shapes: `UnitPrice * Quantity` for four line
subtotals, `Total - WithholdingTax` for Quotation and Receipt amounts, and the
discounted Order subtotal. The target and source-plan expressions both cast
the final result to `numeric(18,2)`.

This equivalence applies only while the referenced inputs retain their signed
types: `UnitPrice`, `Total`, and `WithholdingTax` are `numeric(18,2)`;
`Quantity` is `integer`; and `DiscountPercent` is `numeric(5,2)`. Other column
type drift still changes the whole-schema fingerprint.

- `numeric(18,2) * integer` has fewer than 27 integral digits and exactly two
  fractional digits. The source's intermediate `numeric(29,2)` cast cannot
  round or overflow it.
- Multiplying that product by `numeric(5,2)` has fewer than 30 integral digits
  and exactly four fractional digits. The source's `numeric(35,4)` cast cannot
  round or overflow it. Division by 100 gives at most six fractional digits;
  the later `numeric(38,7)` and `numeric(38,6)` casts do not round. The
  discounted subtraction remains within both intermediate precisions.
- Subtracting two `numeric(18,2)` values has at most 17 integral digits and
  two fractional digits, so `numeric(19,2)` cannot round or overflow it.

The same final `numeric(18,2)` cast therefore gives the same value or overflow
for each pair; SQL null propagation is unchanged. Disposable PostgreSQL 18
tests compare both expressions at positive, negative, fractional, integer
boundary, and final-overflow inputs. The schema comparison recognizes only
these exact three reviewed pairs and continues to reject an altered column
reference or any other generated expression.

This is a schema-fingerprint classification. It neither changes physical
generated columns nor authorizes production DDL, row migration, or application
deployment. A fresh exact-main source plan and identity-bound production
catalog must verify the remaining facets after merge.

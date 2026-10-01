namespace Legacy.Maliev.DataMigration;

/// <summary>Only the pinned consumer check SQL and exact PG18 deparsed forms are interchangeable.</summary>
internal static class ConsumerCheckPredicateCompatibility
{
    private sealed record Pair(string Source, string Catalog, string[] Columns, string? RestoredCatalog = null);
    private static readonly Dictionary<(string Table, string Name), Pair> Known = new()
    {
        [("InvoiceNotificationCorrelation", "CK_InvoiceNotificationCorrelation_Identity")] = new(
                """
                "InvoiceID" > 0 AND "QuotationID" > 0 AND "Purpose" = 'invoice-issued' AND "SenderServiceSubject" = 'service:legacy-accounting' AND "IntentID" <> '00000000-0000-0000-0000-000000000000'::uuid AND "WorkflowOperationID" <> '00000000-0000-0000-0000-000000000000'::uuid AND "IntentID" <> "WorkflowOperationID" AND octet_length("PayloadBinding") = 32 AND length("OriginIssuer") > 0 AND length("OriginEmployeeSubject") > 0 AND length("OriginServiceSubject") > 0 AND length("SenderIssuer") > 0 AND length("BindingKeyID") > 0 AND "PayloadFrameVersion" = 'notification-payload-v1' AND "BindingVersion" = 'accounting-invoice-notification-hmac-v1'
                """,
                """
                (("InvoiceID" > 0) AND ("QuotationID" > 0) AND (("Purpose")::text = 'invoice-issued'::text) AND (("SenderServiceSubject")::text = 'service:legacy-accounting'::text) AND ("IntentID" <> '00000000-0000-0000-0000-000000000000'::uuid) AND ("WorkflowOperationID" <> '00000000-0000-0000-0000-000000000000'::uuid) AND ("IntentID" <> "WorkflowOperationID") AND (octet_length("PayloadBinding") = 32) AND (length(("OriginIssuer")::text) > 0) AND (length(("OriginEmployeeSubject")::text) > 0) AND (length(("OriginServiceSubject")::text) > 0) AND (length(("SenderIssuer")::text) > 0) AND (length(("BindingKeyID")::text) > 0) AND (("PayloadFrameVersion")::text = 'notification-payload-v1'::text) AND (("BindingVersion")::text = 'accounting-invoice-notification-hmac-v1'::text))
                """,
                ["InvoiceID", "QuotationID", "Purpose", "SenderServiceSubject", "IntentID", "WorkflowOperationID", "PayloadBinding", "OriginIssuer", "OriginEmployeeSubject", "OriginServiceSubject", "SenderIssuer", "BindingKeyID", "PayloadFrameVersion", "BindingVersion"]),
        [("InvoiceNotificationCorrelation", "CK_InvoiceNotificationCorrelation_Receipt")] = new(
                """
                ("RemoteVersion" IS NULL AND "RemoteState" IS NULL AND "RemoteAdmittedAt" IS NULL AND "RemoteUpdatedAt" IS NULL AND "RemoteReceiptBinding" IS NULL) OR ("RemoteVersion" IS NOT NULL AND "RemoteVersion">0 AND "RemoteState" IS NOT NULL AND "RemoteAdmittedAt" IS NOT NULL AND "RemoteUpdatedAt" IS NOT NULL AND "RemoteReceiptBinding" IS NOT NULL AND octet_length("RemoteReceiptBinding")=32 AND "RemoteUpdatedAt">="RemoteAdmittedAt" AND (("RemoteState"='admitted' AND "RemoteVersion"=1) OR ("RemoteState"='submitting' AND "RemoteVersion"=2) OR ("RemoteState" IN ('outcomeUnknown','providerAccepted') AND "RemoteVersion"=3)))
                """,
                """
                ((("RemoteVersion" IS NULL) AND ("RemoteState" IS NULL) AND ("RemoteAdmittedAt" IS NULL) AND ("RemoteUpdatedAt" IS NULL) AND ("RemoteReceiptBinding" IS NULL)) OR (("RemoteVersion" IS NOT NULL) AND ("RemoteVersion" > 0) AND ("RemoteState" IS NOT NULL) AND ("RemoteAdmittedAt" IS NOT NULL) AND ("RemoteUpdatedAt" IS NOT NULL) AND ("RemoteReceiptBinding" IS NOT NULL) AND (octet_length("RemoteReceiptBinding") = 32) AND ("RemoteUpdatedAt" >= "RemoteAdmittedAt") AND (((("RemoteState")::text = 'admitted'::text) AND ("RemoteVersion" = 1)) OR ((("RemoteState")::text = 'submitting'::text) AND ("RemoteVersion" = 2)) OR ((("RemoteState")::text = ANY ((ARRAY['outcomeUnknown'::character varying, 'providerAccepted'::character varying])::text[])) AND ("RemoteVersion" = 3)))))
                """,
                ["RemoteVersion", "RemoteState", "RemoteAdmittedAt", "RemoteUpdatedAt", "RemoteReceiptBinding"],
                """
                ((("RemoteVersion" IS NULL) AND ("RemoteState" IS NULL) AND ("RemoteAdmittedAt" IS NULL) AND ("RemoteUpdatedAt" IS NULL) AND ("RemoteReceiptBinding" IS NULL)) OR (("RemoteVersion" IS NOT NULL) AND ("RemoteVersion" > 0) AND ("RemoteState" IS NOT NULL) AND ("RemoteAdmittedAt" IS NOT NULL) AND ("RemoteUpdatedAt" IS NOT NULL) AND ("RemoteReceiptBinding" IS NOT NULL) AND (octet_length("RemoteReceiptBinding") = 32) AND ("RemoteUpdatedAt" >= "RemoteAdmittedAt") AND (((("RemoteState")::text = 'admitted'::text) AND ("RemoteVersion" = 1)) OR ((("RemoteState")::text = 'submitting'::text) AND ("RemoteVersion" = 2)) OR ((("RemoteState")::text = ANY (ARRAY[('outcomeUnknown'::character varying)::text, ('providerAccepted'::character varying)::text])) AND ("RemoteVersion" = 3)))))
                """),
        [("InvoiceNotificationCorrelation", "CK_InvoiceNotificationCorrelation_ReceiptPhase")] = new(
                """
                ("Phase" IN ('Prepared','AdmissionIssued') AND "RemoteVersion" IS NULL) OR ("Phase" IN ('Admitted','ExecutionIssued') AND "RemoteVersion" IS NOT NULL AND "RemoteState"='admitted') OR ("Phase"='OutcomeUnknown' AND "RemoteVersion" IS NOT NULL AND "RemoteState" IN ('submitting','outcomeUnknown')) OR ("Phase"='ProviderAccepted' AND "RemoteVersion" IS NOT NULL AND "RemoteState"='providerAccepted')
                """,
                """
                (((("Phase")::text = ANY ((ARRAY['Prepared'::character varying, 'AdmissionIssued'::character varying])::text[])) AND ("RemoteVersion" IS NULL)) OR ((("Phase")::text = ANY ((ARRAY['Admitted'::character varying, 'ExecutionIssued'::character varying])::text[])) AND ("RemoteVersion" IS NOT NULL) AND (("RemoteState")::text = 'admitted'::text)) OR ((("Phase")::text = 'OutcomeUnknown'::text) AND ("RemoteVersion" IS NOT NULL) AND (("RemoteState")::text = ANY ((ARRAY['submitting'::character varying, 'outcomeUnknown'::character varying])::text[]))) OR ((("Phase")::text = 'ProviderAccepted'::text) AND ("RemoteVersion" IS NOT NULL) AND (("RemoteState")::text = 'providerAccepted'::text)))
                """,
                ["Phase", "RemoteVersion", "RemoteState"],
                """
                (((("Phase")::text = ANY (ARRAY[('Prepared'::character varying)::text, ('AdmissionIssued'::character varying)::text])) AND ("RemoteVersion" IS NULL)) OR ((("Phase")::text = ANY (ARRAY[('Admitted'::character varying)::text, ('ExecutionIssued'::character varying)::text])) AND ("RemoteVersion" IS NOT NULL) AND (("RemoteState")::text = 'admitted'::text)) OR ((("Phase")::text = 'OutcomeUnknown'::text) AND ("RemoteVersion" IS NOT NULL) AND (("RemoteState")::text = ANY (ARRAY[('submitting'::character varying)::text, ('outcomeUnknown'::character varying)::text]))) OR ((("Phase")::text = 'ProviderAccepted'::text) AND ("RemoteVersion" IS NOT NULL) AND (("RemoteState")::text = 'providerAccepted'::text)))
                """),
        [("InvoiceNotificationCorrelation", "CK_InvoiceNotificationCorrelation_State")] = new(
                """
                "Version" > 0 AND ("RemoteVersion" IS NULL OR "RemoteVersion" > 0) AND "UpdatedAt" >= "CreatedAt" AND "Phase" IN ('Prepared','AdmissionIssued','Admitted','ExecutionIssued','OutcomeUnknown','ProviderAccepted','RejectedBeforeSubmission') AND ("AdmissionIssuedAt" IS NULL OR "AdmissionIssuedAt" >= "CreatedAt") AND ("ExecutionIssuedAt" IS NULL OR ("AdmissionIssuedAt" IS NOT NULL AND "ExecutionIssuedAt" >= "AdmissionIssuedAt")) AND ("Phase" = 'Prepared' OR "AdmissionIssuedAt" IS NOT NULL) AND ("Phase" <> 'Prepared' OR ("AdmissionIssuedAt" IS NULL AND "ExecutionIssuedAt" IS NULL AND "RemoteVersion" IS NULL)) AND ("Phase" <> 'AdmissionIssued' OR ("AdmissionIssuedAt" IS NOT NULL AND "ExecutionIssuedAt" IS NULL)) AND ("Phase" <> 'Admitted' OR ("AdmissionIssuedAt" IS NOT NULL AND "ExecutionIssuedAt" IS NULL AND "RemoteVersion" IS NOT NULL)) AND ("Phase" <> 'ExecutionIssued' OR ("ExecutionIssuedAt" IS NOT NULL AND "RemoteVersion" IS NOT NULL)) AND ("Phase" NOT IN ('OutcomeUnknown','ProviderAccepted') OR ("ExecutionIssuedAt" IS NOT NULL AND "RemoteVersion" IS NOT NULL)) AND ("Phase" NOT IN ('ProviderAccepted','RejectedBeforeSubmission') OR "RemoteVersion" IS NOT NULL)
                """,
                """
                (("Version" > 0) AND (("RemoteVersion" IS NULL) OR ("RemoteVersion" > 0)) AND ("UpdatedAt" >= "CreatedAt") AND (("Phase")::text = ANY ((ARRAY['Prepared'::character varying, 'AdmissionIssued'::character varying, 'Admitted'::character varying, 'ExecutionIssued'::character varying, 'OutcomeUnknown'::character varying, 'ProviderAccepted'::character varying, 'RejectedBeforeSubmission'::character varying])::text[])) AND (("AdmissionIssuedAt" IS NULL) OR ("AdmissionIssuedAt" >= "CreatedAt")) AND (("ExecutionIssuedAt" IS NULL) OR (("AdmissionIssuedAt" IS NOT NULL) AND ("ExecutionIssuedAt" >= "AdmissionIssuedAt"))) AND ((("Phase")::text = 'Prepared'::text) OR ("AdmissionIssuedAt" IS NOT NULL)) AND ((("Phase")::text <> 'Prepared'::text) OR (("AdmissionIssuedAt" IS NULL) AND ("ExecutionIssuedAt" IS NULL) AND ("RemoteVersion" IS NULL))) AND ((("Phase")::text <> 'AdmissionIssued'::text) OR (("AdmissionIssuedAt" IS NOT NULL) AND ("ExecutionIssuedAt" IS NULL))) AND ((("Phase")::text <> 'Admitted'::text) OR (("AdmissionIssuedAt" IS NOT NULL) AND ("ExecutionIssuedAt" IS NULL) AND ("RemoteVersion" IS NOT NULL))) AND ((("Phase")::text <> 'ExecutionIssued'::text) OR (("ExecutionIssuedAt" IS NOT NULL) AND ("RemoteVersion" IS NOT NULL))) AND ((("Phase")::text <> ALL ((ARRAY['OutcomeUnknown'::character varying, 'ProviderAccepted'::character varying])::text[])) OR (("ExecutionIssuedAt" IS NOT NULL) AND ("RemoteVersion" IS NOT NULL))) AND ((("Phase")::text <> ALL ((ARRAY['ProviderAccepted'::character varying, 'RejectedBeforeSubmission'::character varying])::text[])) OR ("RemoteVersion" IS NOT NULL)))
                """,
                ["Version", "RemoteVersion", "UpdatedAt", "CreatedAt", "Phase", "AdmissionIssuedAt", "ExecutionIssuedAt"],
                """
                (("Version" > 0) AND (("RemoteVersion" IS NULL) OR ("RemoteVersion" > 0)) AND ("UpdatedAt" >= "CreatedAt") AND (("Phase")::text = ANY (ARRAY[('Prepared'::character varying)::text, ('AdmissionIssued'::character varying)::text, ('Admitted'::character varying)::text, ('ExecutionIssued'::character varying)::text, ('OutcomeUnknown'::character varying)::text, ('ProviderAccepted'::character varying)::text, ('RejectedBeforeSubmission'::character varying)::text])) AND (("AdmissionIssuedAt" IS NULL) OR ("AdmissionIssuedAt" >= "CreatedAt")) AND (("ExecutionIssuedAt" IS NULL) OR (("AdmissionIssuedAt" IS NOT NULL) AND ("ExecutionIssuedAt" >= "AdmissionIssuedAt"))) AND ((("Phase")::text = 'Prepared'::text) OR ("AdmissionIssuedAt" IS NOT NULL)) AND ((("Phase")::text <> 'Prepared'::text) OR (("AdmissionIssuedAt" IS NULL) AND ("ExecutionIssuedAt" IS NULL) AND ("RemoteVersion" IS NULL))) AND ((("Phase")::text <> 'AdmissionIssued'::text) OR (("AdmissionIssuedAt" IS NOT NULL) AND ("ExecutionIssuedAt" IS NULL))) AND ((("Phase")::text <> 'Admitted'::text) OR (("AdmissionIssuedAt" IS NOT NULL) AND ("ExecutionIssuedAt" IS NULL) AND ("RemoteVersion" IS NOT NULL))) AND ((("Phase")::text <> 'ExecutionIssued'::text) OR (("ExecutionIssuedAt" IS NOT NULL) AND ("RemoteVersion" IS NOT NULL))) AND ((("Phase")::text <> ALL (ARRAY[('OutcomeUnknown'::character varying)::text, ('ProviderAccepted'::character varying)::text])) OR (("ExecutionIssuedAt" IS NOT NULL) AND ("RemoteVersion" IS NOT NULL))) AND ((("Phase")::text <> ALL (ARRAY[('ProviderAccepted'::character varying)::text, ('RejectedBeforeSubmission'::character varying)::text])) OR ("RemoteVersion" IS NOT NULL)))
                """),
        [("EmployeeRecoveryEffects", "CK_EmployeeRecoveryEffects_Binding")] = new(
                """
                length("TokenSha256") = 64 AND length("OwnerSubject") > 0 AND length("BeforeSecurityStamp") > 0 AND length("AfterSecurityStamp") > 0
                """,
                """
                ((length(("TokenSha256")::text) = 64) AND (length(("OwnerSubject")::text) > 0) AND (length("BeforeSecurityStamp") > 0) AND (length("AfterSecurityStamp") > 0))
                """,
                ["TokenSha256", "OwnerSubject", "BeforeSecurityStamp", "AfterSecurityStamp"]),
        [("EmployeeRecoveryEffects", "CK_EmployeeRecoveryEffects_PurposePayload")] = new(
                """
                ("Purpose" = 'employee-password-reset' AND "PasswordPayloadHash" IS NOT NULL) OR ("Purpose" = 'employee-email-confirmation' AND "PasswordPayloadHash" IS NULL)
                """,
                """
                (((("Purpose")::text = 'employee-password-reset'::text) AND ("PasswordPayloadHash" IS NOT NULL)) OR ((("Purpose")::text = 'employee-email-confirmation'::text) AND ("PasswordPayloadHash" IS NULL)))
                """,
                ["Purpose", "PasswordPayloadHash"]),
    };

    internal static string Canonicalize(PostgreSqlSchemaFingerprint.ConstraintShape constraint)
    {
        if (constraint.Kind != 'c' || constraint.Schema != "public" ||
            !Known.TryGetValue((constraint.Table, constraint.Name), out Pair? pair) ||
            !constraint.Columns.SequenceEqual(pair.Columns, StringComparer.Ordinal))
        {
            return QuotationCheckPredicateCompatibility.Canonicalize(constraint);
        }

        string expression = SchemaExpressionCanonicalizer.Canonicalize(constraint.Expression);
        string source = SchemaExpressionCanonicalizer.Canonicalize(pair.Source);
        string catalog = SchemaExpressionCanonicalizer.Canonicalize(pair.Catalog);
        string? restored = pair.RestoredCatalog is null ? null : SchemaExpressionCanonicalizer.Canonicalize(pair.RestoredCatalog);
        return expression == source || expression == catalog || expression == restored ? source : expression;
    }
}

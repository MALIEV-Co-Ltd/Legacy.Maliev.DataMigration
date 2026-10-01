namespace Legacy.Maliev.DataMigration;

/// <summary>Immutable target-only shapes reviewed against Accounting 1913979 and Auth 51afbbd.</summary>
internal static class ApprovedConsumerTargetExtensionShapes
{
    internal static IReadOnlyList<TableCopyPlan> Invoice()
    {
        return [Admission(), Correlation()];
    }

    internal static IReadOnlyList<TableCopyPlan> CustomerIdentity()
    {
        return [CustomerOperation()];
    }

    internal static IReadOnlyList<TableCopyPlan> EmployeeIdentity()
    {
        return [EmployeeEffect()];
    }

    private static TableCopyPlan Shape(string table, (string Name, string Type)[] columns, string key, string[] nullable)
    {
        return new("target-only", table, "public", table, columns.Select(x => x.Name).ToArray(), [key])
        {
            ColumnTypes = columns.ToDictionary(x => x.Name, x => x.Type, StringComparer.Ordinal),
            NullableColumns = nullable,
            PrimaryKey = new($"PK_{table}", [key]),
        };
    }

    private static TableCopyPlan Admission()
    {
        return Shape("InvoiceCreationAdmission",
        [("OperationID", "uuid"), ("QuotationID", "integer"), ("EmployeeSubject", "character varying(256)"),
         ("ServiceSubject", "character varying(128)"), ("IntentFingerprint", "character varying(64)"),
         ("State", "character varying(32)"), ("ResultJson", "text"), ("CreatedAt", "timestamp with time zone"),
         ("UpdatedAt", "timestamp with time zone")], "OperationID", ["ResultJson"]) with
        { CheckConstraints = [new("CK_InvoiceCreationAdmission_Quotation", "\"QuotationID\" > 0") { Columns = ["QuotationID"] }] };
    }

    private static TableCopyPlan CustomerOperation()
    {
        return Shape("CustomerIdentityCreateOperations",
        [("Id", "bigint"), ("ServiceSubject", "character varying(256)"), ("OperationKey", "uuid"),
         ("DatabaseId", "integer"), ("IdentityId", "character varying(450)"), ("PayloadSalt", "bytea"), ("PayloadHash", "bytea")], "Id", []) with
        {
            Identities = [new("Id", 1, 1, 1, false)],
            Indexes = [new("IX_CustomerIdentityCreateOperations_ServiceSubject_OperationKey", ["ServiceSubject", "OperationKey"], true),
                new("IX_CustomerIdentityCreateOperations_DatabaseId", ["DatabaseId"], true)],
        };
    }

    private static TableCopyPlan EmployeeEffect()
    {
        return Shape("EmployeeRecoveryEffects",
        [("ActionId", "uuid"), ("TokenSha256", "character varying(64)"), ("Purpose", "character varying(32)"),
         ("OwnerSubject", "character varying(256)"), ("IdentityId", "character varying(450)"),
         ("NormalizedEmail", "character varying(256)"), ("BeforeSecurityStamp", "text"), ("AfterSecurityStamp", "text"),
         ("AfterConcurrencyStamp", "text"), ("PasswordPayloadHash", "text"), ("AppliedAt", "timestamp with time zone"),
         ("FinalizedAcknowledgedAt", "timestamp with time zone")], "ActionId", ["PasswordPayloadHash", "FinalizedAcknowledgedAt"]) with
        {
            CheckConstraints =
            [new("CK_EmployeeRecoveryEffects_PurposePayload", "(\"Purpose\" = 'employee-password-reset' AND \"PasswordPayloadHash\" IS NOT NULL) OR (\"Purpose\" = 'employee-email-confirmation' AND \"PasswordPayloadHash\" IS NULL)") { Columns = ["Purpose", "PasswordPayloadHash"] },
             new("CK_EmployeeRecoveryEffects_Binding", "length(\"TokenSha256\") = 64 AND length(\"OwnerSubject\") > 0 AND length(\"BeforeSecurityStamp\") > 0 AND length(\"AfterSecurityStamp\") > 0") { Columns = ["TokenSha256", "OwnerSubject", "BeforeSecurityStamp", "AfterSecurityStamp"] }],
            Indexes = [new("IX_EmployeeRecoveryEffects_TokenSha256_Purpose", ["TokenSha256", "Purpose"], true),
                new("IX_EmployeeRecoveryEffects_IdentityId_FinalizedAcknowledgedAt", ["IdentityId", "FinalizedAcknowledgedAt"], false),
                new("IX_EmployeeRecoveryEffects_FinalizedAcknowledgedAt_AppliedAt", ["FinalizedAcknowledgedAt", "AppliedAt"], false)],
        };
    }

    private static TableCopyPlan Correlation()
    {
        return Shape("InvoiceNotificationCorrelation",
        [("IntentID", "uuid"), ("InvoiceID", "integer"), ("Purpose", "character varying(32)"), ("QuotationID", "integer"),
         ("WorkflowOperationID", "uuid"), ("OriginIssuer", "character varying(512)"), ("OriginEmployeeSubject", "character varying(256)"),
         ("OriginServiceSubject", "character varying(128)"), ("SenderIssuer", "character varying(512)"),
         ("SenderServiceSubject", "character varying(128)"), ("PayloadFrameVersion", "character varying(64)"),
         ("BindingVersion", "character varying(64)"), ("BindingKeyID", "character varying(64)"), ("PayloadBinding", "bytea"),
         ("Phase", "character varying(32)"), ("Version", "bigint"), ("RemoteVersion", "bigint"), ("CreatedAt", "timestamp with time zone"),
         ("UpdatedAt", "timestamp with time zone"), ("AdmissionIssuedAt", "timestamp with time zone"), ("ExecutionIssuedAt", "timestamp with time zone"),
         ("RemoteAdmittedAt", "timestamp with time zone"), ("RemoteReceiptBinding", "bytea"), ("RemoteState", "character varying(32)"),
         ("RemoteUpdatedAt", "timestamp with time zone")], "IntentID",
        ["RemoteVersion", "AdmissionIssuedAt", "ExecutionIssuedAt", "RemoteAdmittedAt", "RemoteReceiptBinding", "RemoteState", "RemoteUpdatedAt"]) with
        {
            UniqueConstraints = [new("UQ_InvoiceNotificationCorrelation_InvoicePurpose", ["InvoiceID", "Purpose"])],
            CheckConstraints =
            [new("CK_InvoiceNotificationCorrelation_Identity", "\"InvoiceID\" > 0 AND \"QuotationID\" > 0 AND \"Purpose\" = 'invoice-issued' AND \"SenderServiceSubject\" = 'service:legacy-accounting' AND \"IntentID\" <> '00000000-0000-0000-0000-000000000000'::uuid AND \"WorkflowOperationID\" <> '00000000-0000-0000-0000-000000000000'::uuid AND \"IntentID\" <> \"WorkflowOperationID\" AND octet_length(\"PayloadBinding\") = 32 AND length(\"OriginIssuer\") > 0 AND length(\"OriginEmployeeSubject\") > 0 AND length(\"OriginServiceSubject\") > 0 AND length(\"SenderIssuer\") > 0 AND length(\"BindingKeyID\") > 0 AND \"PayloadFrameVersion\" = 'notification-payload-v1' AND \"BindingVersion\" = 'accounting-invoice-notification-hmac-v1'") { Columns = ["InvoiceID", "QuotationID", "Purpose", "SenderServiceSubject", "IntentID", "WorkflowOperationID", "PayloadBinding", "OriginIssuer", "OriginEmployeeSubject", "OriginServiceSubject", "SenderIssuer", "BindingKeyID", "PayloadFrameVersion", "BindingVersion"] },
             new("CK_InvoiceNotificationCorrelation_State", "\"Version\" > 0 AND (\"RemoteVersion\" IS NULL OR \"RemoteVersion\" > 0) AND \"UpdatedAt\" >= \"CreatedAt\" AND \"Phase\" IN ('Prepared','AdmissionIssued','Admitted','ExecutionIssued','OutcomeUnknown','ProviderAccepted','RejectedBeforeSubmission') AND (\"AdmissionIssuedAt\" IS NULL OR \"AdmissionIssuedAt\" >= \"CreatedAt\") AND (\"ExecutionIssuedAt\" IS NULL OR (\"AdmissionIssuedAt\" IS NOT NULL AND \"ExecutionIssuedAt\" >= \"AdmissionIssuedAt\")) AND (\"Phase\" = 'Prepared' OR \"AdmissionIssuedAt\" IS NOT NULL) AND (\"Phase\" <> 'Prepared' OR (\"AdmissionIssuedAt\" IS NULL AND \"ExecutionIssuedAt\" IS NULL AND \"RemoteVersion\" IS NULL)) AND (\"Phase\" <> 'AdmissionIssued' OR (\"AdmissionIssuedAt\" IS NOT NULL AND \"ExecutionIssuedAt\" IS NULL)) AND (\"Phase\" <> 'Admitted' OR (\"AdmissionIssuedAt\" IS NOT NULL AND \"ExecutionIssuedAt\" IS NULL AND \"RemoteVersion\" IS NOT NULL)) AND (\"Phase\" <> 'ExecutionIssued' OR (\"ExecutionIssuedAt\" IS NOT NULL AND \"RemoteVersion\" IS NOT NULL)) AND (\"Phase\" NOT IN ('OutcomeUnknown','ProviderAccepted') OR (\"ExecutionIssuedAt\" IS NOT NULL AND \"RemoteVersion\" IS NOT NULL)) AND (\"Phase\" NOT IN ('ProviderAccepted','RejectedBeforeSubmission') OR \"RemoteVersion\" IS NOT NULL)") { Columns = ["Version", "RemoteVersion", "UpdatedAt", "CreatedAt", "Phase", "AdmissionIssuedAt", "ExecutionIssuedAt"] },
             new("CK_InvoiceNotificationCorrelation_Receipt", "(\"RemoteVersion\" IS NULL AND \"RemoteState\" IS NULL AND \"RemoteAdmittedAt\" IS NULL AND \"RemoteUpdatedAt\" IS NULL AND \"RemoteReceiptBinding\" IS NULL) OR (\"RemoteVersion\" IS NOT NULL AND \"RemoteVersion\">0 AND \"RemoteState\" IS NOT NULL AND \"RemoteAdmittedAt\" IS NOT NULL AND \"RemoteUpdatedAt\" IS NOT NULL AND \"RemoteReceiptBinding\" IS NOT NULL AND octet_length(\"RemoteReceiptBinding\")=32 AND \"RemoteUpdatedAt\">=\"RemoteAdmittedAt\" AND ((\"RemoteState\"='admitted' AND \"RemoteVersion\"=1) OR (\"RemoteState\"='submitting' AND \"RemoteVersion\"=2) OR (\"RemoteState\" IN ('outcomeUnknown','providerAccepted') AND \"RemoteVersion\"=3)))") { Columns = ["RemoteVersion", "RemoteState", "RemoteAdmittedAt", "RemoteUpdatedAt", "RemoteReceiptBinding"] },
             new("CK_InvoiceNotificationCorrelation_ReceiptPhase", "(\"Phase\" IN ('Prepared','AdmissionIssued') AND \"RemoteVersion\" IS NULL) OR (\"Phase\" IN ('Admitted','ExecutionIssued') AND \"RemoteVersion\" IS NOT NULL AND \"RemoteState\"='admitted') OR (\"Phase\"='OutcomeUnknown' AND \"RemoteVersion\" IS NOT NULL AND \"RemoteState\" IN ('submitting','outcomeUnknown')) OR (\"Phase\"='ProviderAccepted' AND \"RemoteVersion\" IS NOT NULL AND \"RemoteState\"='providerAccepted')") { Columns = ["Phase", "RemoteVersion", "RemoteState"] }],
        };
    }
}

namespace Legacy.Maliev.DataMigration;

/// <summary>Exact target-only contracts: Customer 87422ad9, File 92cead32, Order 7847203d.</summary>
internal static class ApprovedCurrentConsumerTargetShapes
{
    internal static IReadOnlyList<TableCopyPlan> ForDatabase(string database)
    {
        return database switch
        {
            "Customer" => [CustomerCreateOperation(), QuotationProfileCompletionOperation()],
            "Order" => [OrderDeletionIntent()],
            "Upload" => [StorageMoveJournal(), QuarantineUploadIntent(), InstantQuoteUploadSession(), InstantQuoteFinalization(), InstantQuoteUploadFile()],
            _ => [],
        };
    }

    private static TableCopyPlan CustomerCreateOperation()
    {
        return new(
        "target-only", "CustomerCreateOperation", "public", "CustomerCreateOperation",
        ["Key", "ActorHash", "RequestHash", "CustomerId", "ResponseJson", "CreatedAt"], ["Key"])
        {
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Key"] = "uuid",
                ["ActorHash"] = "character varying(64)",
                ["RequestHash"] = "character varying(64)",
                ["CustomerId"] = "integer",
                ["ResponseJson"] = "jsonb",
                ["CreatedAt"] = "timestamp with time zone",
            },
            NullableColumns = [],
            PrimaryKey = new("PK_CustomerCreateOperation", ["Key"]),
            Collations = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["ActorHash"] = "C",
                ["RequestHash"] = "C",
            },
        };
    }

    private static TableCopyPlan QuotationProfileCompletionOperation()
    {
        return new(
        "target-only", "QuotationProfileCompletionOperation", "public", "QuotationProfileCompletionOperation",
        ["CustomerId", "Key", "ActorHash", "RequestHash", "CompletionId", "Changed", "CreatedAt"], ["CustomerId", "Key"])
        {
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["CustomerId"] = "integer",
                ["Key"] = "uuid",
                ["ActorHash"] = "character varying(64)",
                ["RequestHash"] = "character varying(64)",
                ["CompletionId"] = "uuid",
                ["Changed"] = "boolean",
                ["CreatedAt"] = "timestamp with time zone",
            },
            NullableColumns = [],
            PrimaryKey = new("PK_QuotationProfileCompletionOperation", ["CustomerId", "Key"]),
            Collations = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["ActorHash"] = "C",
                ["RequestHash"] = "C",
            },
        };
    }

    private static TableCopyPlan StorageMoveJournal()
    {
        return new(
        "target-only", "StorageMoveJournal", "public", "StorageMoveJournal",
        ["OperationId", "ScanClean", "SourceBucket", "SourceObjectName", "SourceGeneration", "DestinationBucket", "DestinationObjectName", "DestinationGeneration", "State", "CreatedAt", "ModifiedAt"], ["OperationId"])
        {
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["OperationId"] = "uuid",
                ["ScanClean"] = "boolean",
                ["SourceBucket"] = "character varying(255)",
                ["SourceObjectName"] = "character varying(1024)",
                ["SourceGeneration"] = "bigint",
                ["DestinationBucket"] = "character varying(255)",
                ["DestinationObjectName"] = "character varying(1024)",
                ["DestinationGeneration"] = "bigint",
                ["State"] = "character varying(32)",
                ["CreatedAt"] = "timestamp with time zone",
                ["ModifiedAt"] = "timestamp with time zone",
            },
            NullableColumns = ["DestinationGeneration"],
            PrimaryKey = new("PK_StorageMoveJournal", ["OperationId"]),
            CheckConstraints =
        [
            new("CK_StorageMoveJournal_DestinationGeneration", "\"DestinationGeneration\" IS NULL OR \"DestinationGeneration\" > 0") { Columns = ["DestinationGeneration"] },
            new("CK_StorageMoveJournal_SourceGeneration", "\"SourceGeneration\" > 0") { Columns = ["SourceGeneration"] },
        ],
            Indexes =
        [
            new("IX_StorageMoveJournal_DestinationBucket_DestinationObjectName", ["DestinationBucket", "DestinationObjectName"], false),
            new("IX_StorageMoveJournal_SourceBucket_SourceObjectName", ["SourceBucket", "SourceObjectName"], false),
        ],
            Collations = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["SourceBucket"] = "C",
                ["SourceObjectName"] = "C",
                ["DestinationBucket"] = "C",
                ["DestinationObjectName"] = "C",
                ["State"] = "C",
            },
        };
    }

    private static TableCopyPlan QuarantineUploadIntent()
    {
        return new(
        "target-only", "QuarantineUploadIntent", "public", "QuarantineUploadIntent",
        ["OperationId", "ParentOperationId", "Bucket", "ObjectName", "ContentType", "DeclaredSize", "AcknowledgedGeneration", "State", "CreatedAt", "ModifiedAt"], ["OperationId"])
        {
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["OperationId"] = "uuid",
                ["ParentOperationId"] = "uuid",
                ["Bucket"] = "character varying(255)",
                ["ObjectName"] = "character varying(1024)",
                ["ContentType"] = "character varying(255)",
                ["DeclaredSize"] = "bigint",
                ["AcknowledgedGeneration"] = "bigint",
                ["State"] = "character varying(32)",
                ["CreatedAt"] = "timestamp with time zone",
                ["ModifiedAt"] = "timestamp with time zone",
            },
            NullableColumns = ["AcknowledgedGeneration"],
            PrimaryKey = new("PK_QuarantineUploadIntent", ["OperationId"]),
            CheckConstraints =
        [
            new("CK_QuarantineUploadIntent_DeclaredSize", "\"DeclaredSize\" > 0") { Columns = ["DeclaredSize"] },
            new("CK_QuarantineUploadIntent_Generation", "\"AcknowledgedGeneration\" IS NULL OR \"AcknowledgedGeneration\" > 0") { Columns = ["AcknowledgedGeneration"] },
        ],
            Indexes =
        [
            new("IX_QuarantineUploadIntent_Bucket_ObjectName", ["Bucket", "ObjectName"], false),
        ],
            Collations = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Bucket"] = "C",
                ["ObjectName"] = "C",
                ["ContentType"] = "C",
                ["State"] = "C",
            },
        };
    }

    private static TableCopyPlan InstantQuoteUploadSession()
    {
        return new(
        "target-only", "InstantQuoteUploadSession", "public", "InstantQuoteUploadSession",
        ["Id", "OwnerSubject", "IsAuthenticated", "TokenHash", "ExpiresAt", "CreatedAt"], ["Id"])
        {
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Id"] = "uuid",
                ["OwnerSubject"] = "character varying(512)",
                ["IsAuthenticated"] = "boolean",
                ["TokenHash"] = "bytea",
                ["ExpiresAt"] = "timestamp with time zone",
                ["CreatedAt"] = "timestamp with time zone",
            },
            NullableColumns = ["OwnerSubject"],
            PrimaryKey = new("PK_InstantQuoteUploadSession", ["Id"]),
            CheckConstraints =
        [
            new("CK_InstantQuoteUploadSession_TokenHash_Length", "octet_length(\"TokenHash\") = 32") { Columns = ["TokenHash"] },
        ],
            Collations = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["OwnerSubject"] = "C",
            },
        };
    }

    private static TableCopyPlan InstantQuoteFinalization()
    {
        return new(
        "target-only", "InstantQuoteFinalization", "public", "InstantQuoteFinalization",
        ["Id", "SessionId", "IdempotencyKeyHash", "RequestFingerprint", "QuotationRequestId", "SelectedFileIds", "State", "CreatedAt", "ModifiedAt"], ["Id"])
        {
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Id"] = "uuid",
                ["SessionId"] = "uuid",
                ["IdempotencyKeyHash"] = "bytea",
                ["RequestFingerprint"] = "character(64)",
                ["QuotationRequestId"] = "integer",
                ["SelectedFileIds"] = "uuid[]",
                ["State"] = "character varying(16)",
                ["CreatedAt"] = "timestamp with time zone",
                ["ModifiedAt"] = "timestamp with time zone",
            },
            NullableColumns = [],
            PrimaryKey = new("PK_InstantQuoteFinalization", ["Id"]),
            CheckConstraints =
        [
            new("CK_InstantQuoteFinalization_Fingerprint", "\"RequestFingerprint\" ~ '^[0-9a-f]{64}$'") { Columns = ["RequestFingerprint"] },
            new("CK_InstantQuoteFinalization_KeyHash_Length", "octet_length(\"IdempotencyKeyHash\") = 32") { Columns = ["IdempotencyKeyHash"] },
            new("CK_InstantQuoteFinalization_QuotationRequestId_Positive", "\"QuotationRequestId\" > 0") { Columns = ["QuotationRequestId"] },
        ],
            ForeignKeys =
        [
            new("FK_InstantQuoteFinalization_InstantQuoteUploadSession_SessionId", ["SessionId"], "public", "InstantQuoteUploadSession", ["Id"]) { OnDelete = ReferentialAction.Cascade },
        ],
            Indexes =
        [
            new("IX_InstantQuoteFinalization_SessionId_IdempotencyKeyHash", ["SessionId", "IdempotencyKeyHash"], true),
        ],
            Collations = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["RequestFingerprint"] = "C",
                ["State"] = "C",
            },
        };
    }

    private static TableCopyPlan InstantQuoteUploadFile()
    {
        return new(
        "target-only", "InstantQuoteUploadFile", "public", "InstantQuoteUploadFile",
        ["Id", "SessionId", "IdempotencyKeyHash", "RequestFingerprint", "OriginalFileName", "ValidatedExtension", "ValidatedContentType", "ExpectedSha256", "ActualSha256", "ActualSizeBytes", "GcsGeneration", "TemporaryCleanupCompleted", "TemporaryBucket", "TemporaryObjectName", "FinalBucket", "FinalObjectName", "FinalizedQuotationRequestId", "State", "CreatedAt", "ModifiedAt"], ["Id"])
        {
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Id"] = "uuid",
                ["SessionId"] = "uuid",
                ["IdempotencyKeyHash"] = "bytea",
                ["RequestFingerprint"] = "character(64)",
                ["OriginalFileName"] = "character varying(1024)",
                ["ValidatedExtension"] = "character varying(16)",
                ["ValidatedContentType"] = "character varying(255)",
                ["ExpectedSha256"] = "character(64)",
                ["ActualSha256"] = "character(64)",
                ["ActualSizeBytes"] = "bigint",
                ["GcsGeneration"] = "bigint",
                ["TemporaryCleanupCompleted"] = "boolean",
                ["TemporaryBucket"] = "character varying(255)",
                ["TemporaryObjectName"] = "character varying(1024)",
                ["FinalBucket"] = "character varying(255)",
                ["FinalObjectName"] = "character varying(1024)",
                ["FinalizedQuotationRequestId"] = "integer",
                ["State"] = "character varying(16)",
                ["CreatedAt"] = "timestamp with time zone",
                ["ModifiedAt"] = "timestamp with time zone",
            },
            NullableColumns = ["ActualSha256", "ActualSizeBytes", "GcsGeneration", "FinalBucket", "FinalObjectName", "FinalizedQuotationRequestId"],
            PrimaryKey = new("PK_InstantQuoteUploadFile", ["Id"]),
            DefaultExpressions = new Dictionary<string, string>(StringComparer.Ordinal) { ["TemporaryCleanupCompleted"] = "false" },
            CheckConstraints =
        [
            new("CK_InstantQuoteUploadFile_ActualSha256", "\"ActualSha256\" IS NULL OR \"ActualSha256\" ~ '^[0-9a-f]{64}$'") { Columns = ["ActualSha256"] },
            new("CK_InstantQuoteUploadFile_ExpectedSha256", "\"ExpectedSha256\" ~ '^[0-9a-f]{64}$'") { Columns = ["ExpectedSha256"] },
            new("CK_InstantQuoteUploadFile_FinalizedQuotationRequestId_Positive", "\"FinalizedQuotationRequestId\" IS NULL OR \"FinalizedQuotationRequestId\" > 0") { Columns = ["FinalizedQuotationRequestId"] },
            new("CK_InstantQuoteUploadFile_Fingerprint", "\"RequestFingerprint\" ~ '^[0-9a-f]{64}$'") { Columns = ["RequestFingerprint"] },
            new("CK_InstantQuoteUploadFile_KeyHash_Length", "octet_length(\"IdempotencyKeyHash\") = 32") { Columns = ["IdempotencyKeyHash"] },
        ],
            ForeignKeys =
        [
            new("FK_InstantQuoteUploadFile_InstantQuoteUploadSession_SessionId", ["SessionId"], "public", "InstantQuoteUploadSession", ["Id"]) { OnDelete = ReferentialAction.Cascade },
        ],
            Indexes =
        [
            new("IX_InstantQuoteUploadFile_SessionId_IdempotencyKeyHash", ["SessionId", "IdempotencyKeyHash"], true),
        ],
            Collations = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["RequestFingerprint"] = "C",
                ["OriginalFileName"] = "C",
                ["ValidatedExtension"] = "C",
                ["ValidatedContentType"] = "C",
                ["ExpectedSha256"] = "C",
                ["ActualSha256"] = "C",
                ["TemporaryBucket"] = "C",
                ["TemporaryObjectName"] = "C",
                ["FinalBucket"] = "C",
                ["FinalObjectName"] = "C",
                ["State"] = "C",
            },
        };
    }

    private static TableCopyPlan OrderDeletionIntent()
    {
        return new(
        "target-only", "OrderDeletionIntent", "public", "OrderDeletionIntent",
        ["OrderId", "DeletionId", "RequestedAtUtc", "StatusCleanupCompletedAtUtc", "CompletedAtUtc", "AttemptCount", "NextAttemptAtUtc"], ["OrderId"])
        {
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["OrderId"] = "integer",
                ["DeletionId"] = "uuid",
                ["RequestedAtUtc"] = "timestamp with time zone",
                ["StatusCleanupCompletedAtUtc"] = "timestamp with time zone",
                ["CompletedAtUtc"] = "timestamp with time zone",
                ["AttemptCount"] = "integer",
                ["NextAttemptAtUtc"] = "timestamp with time zone",
            },
            NullableColumns = ["StatusCleanupCompletedAtUtc", "CompletedAtUtc"],
            PrimaryKey = new("PK_OrderDeletionIntent", ["OrderId"]),
            CheckConstraints =
        [
            new("CK_OrderDeletionIntent_AttemptCount", "\"AttemptCount\" >= 0") { Columns = ["AttemptCount"] },
        ],
            Indexes =
        [
            new("IX_OrderDeletionIntent_DeletionId", ["DeletionId"], true),
            new("IX_OrderDeletionIntent_PendingDue", ["NextAttemptAtUtc", "OrderId"], false) { FilterPredicate = "\"CompletedAtUtc\" IS NULL" },
        ],
            Collations = new Dictionary<string, string>(StringComparer.Ordinal)
            {
            },
        };
    }
}

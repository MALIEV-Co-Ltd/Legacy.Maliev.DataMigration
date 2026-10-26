using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

internal enum CurrentAppOwnedRepairOperation
{
    CreateEightTables = 0,
    RetainedThirtyOneTextCollations = 1,
}

internal sealed record CurrentAppOwnedCollationOperand(
    string Database, string Schema, string Table, string Column, string PostgreSqlType);

/// <summary>Fixed preparation-only operands. This manifest never grants execution authority.</summary>
internal static class CurrentAppOwnedRepairManifest
{
    private const string Domain = "Legacy.Maliev.CurrentAppOwnedAdditiveRepair.v1";
    private static readonly CurrentAppOwnedCollationOperand[] Retained =
    [
        new("Invoice", "public", "InvoiceNotificationCorrelation", "Purpose", "character varying(32)"),
        new("Invoice", "public", "InvoiceNotificationCorrelation", "OriginIssuer", "character varying(512)"),
        new("Invoice", "public", "InvoiceNotificationCorrelation", "OriginEmployeeSubject", "character varying(256)"),
        new("Invoice", "public", "InvoiceNotificationCorrelation", "OriginServiceSubject", "character varying(128)"),
        new("Invoice", "public", "InvoiceNotificationCorrelation", "SenderIssuer", "character varying(512)"),
        new("Invoice", "public", "InvoiceNotificationCorrelation", "SenderServiceSubject", "character varying(128)"),
        new("Invoice", "public", "InvoiceNotificationCorrelation", "PayloadFrameVersion", "character varying(64)"),
        new("Invoice", "public", "InvoiceNotificationCorrelation", "BindingVersion", "character varying(64)"),
        new("Invoice", "public", "InvoiceNotificationCorrelation", "BindingKeyID", "character varying(64)"),
        new("Invoice", "public", "InvoiceNotificationCorrelation", "Phase", "character varying(32)"),
        new("Invoice", "public", "InvoiceNotificationCorrelation", "RemoteState", "character varying(32)"),
        new("Invoice", "public", "InvoiceCreationAdmission", "EmployeeSubject", "character varying(256)"),
        new("Invoice", "public", "InvoiceCreationAdmission", "ServiceSubject", "character varying(128)"),
        new("Invoice", "public", "InvoiceCreationAdmission", "IntentFingerprint", "character varying(64)"),
        new("Invoice", "public", "InvoiceCreationAdmission", "State", "character varying(32)"),
        new("Invoice", "public", "InvoiceCreationAdmission", "ResultJson", "text"),
        new("CustomerIdentity", "public", "CustomerIdentityCreateOperations", "ServiceSubject", "character varying(256)"),
        new("CustomerIdentity", "public", "CustomerIdentityCreateOperations", "IdentityId", "character varying(450)"),
        new("EmployeeIdentity", "public", "EmployeeRecoveryEffects", "TokenSha256", "character varying(64)"),
        new("EmployeeIdentity", "public", "EmployeeRecoveryEffects", "Purpose", "character varying(32)"),
        new("EmployeeIdentity", "public", "EmployeeRecoveryEffects", "OwnerSubject", "character varying(256)"),
        new("EmployeeIdentity", "public", "EmployeeRecoveryEffects", "IdentityId", "character varying(450)"),
        new("EmployeeIdentity", "public", "EmployeeRecoveryEffects", "NormalizedEmail", "character varying(256)"),
        new("EmployeeIdentity", "public", "EmployeeRecoveryEffects", "BeforeSecurityStamp", "text"),
        new("EmployeeIdentity", "public", "EmployeeRecoveryEffects", "AfterSecurityStamp", "text"),
        new("EmployeeIdentity", "public", "EmployeeRecoveryEffects", "AfterConcurrencyStamp", "text"),
        new("EmployeeIdentity", "public", "EmployeeRecoveryEffects", "PasswordPayloadHash", "text"),
        new("Quotation", "public", "QuotationAcceptedOutcome", "EventKey", "character varying(128)"),
        new("Quotation", "public", "QuotationAcceptedOutcome", "AcceptanceOrigin", "character varying(16)"),
        new("QuotationRequest", "public", "RequestCreateIdempotency", "KeyHash", "character(64)"),
        new("QuotationRequest", "public", "RequestCreateIdempotency", "Fingerprint", "character(64)"),
    ];

    internal static CurrentAppOwnedCollationOperand[] RetainedOperands()
    {
        return [.. Retained];
    }

    internal static string CreateEightSql(string database)
    {
        return database switch
        {
            "Customer" => """
            CREATE TABLE public."CustomerCreateOperation" (
              "Key" uuid NOT NULL,
              "ActorHash" character varying(64) COLLATE "C" NOT NULL,
              "RequestHash" character varying(64) COLLATE "C" NOT NULL,
              "CustomerId" integer NOT NULL,
              "ResponseJson" jsonb NOT NULL,
              "CreatedAt" timestamp with time zone NOT NULL,
              CONSTRAINT "PK_CustomerCreateOperation" PRIMARY KEY ("Key")
            );
            CREATE TABLE public."QuotationProfileCompletionOperation" (
              "CustomerId" integer NOT NULL,
              "Key" uuid NOT NULL,
              "ActorHash" character varying(64) COLLATE "C" NOT NULL,
              "RequestHash" character varying(64) COLLATE "C" NOT NULL,
              "CompletionId" uuid NOT NULL,
              "Changed" boolean NOT NULL,
              "CreatedAt" timestamp with time zone NOT NULL,
              CONSTRAINT "PK_QuotationProfileCompletionOperation" PRIMARY KEY ("CustomerId", "Key")
            );
            """,
            "Upload" => """
            CREATE TABLE public."StorageMoveJournal" (
              "OperationId" uuid NOT NULL,
              "ScanClean" boolean NOT NULL,
              "SourceBucket" character varying(255) COLLATE "C" NOT NULL,
              "SourceObjectName" character varying(1024) COLLATE "C" NOT NULL,
              "SourceGeneration" bigint NOT NULL,
              "DestinationBucket" character varying(255) COLLATE "C" NOT NULL,
              "DestinationObjectName" character varying(1024) COLLATE "C" NOT NULL,
              "DestinationGeneration" bigint,
              "State" character varying(32) COLLATE "C" NOT NULL,
              "CreatedAt" timestamp with time zone NOT NULL,
              "ModifiedAt" timestamp with time zone NOT NULL,
              CONSTRAINT "PK_StorageMoveJournal" PRIMARY KEY ("OperationId"),
              CONSTRAINT "CK_StorageMoveJournal_DestinationGeneration" CHECK ("DestinationGeneration" IS NULL OR "DestinationGeneration" > 0),
              CONSTRAINT "CK_StorageMoveJournal_SourceGeneration" CHECK ("SourceGeneration" > 0)
            );
            CREATE INDEX "IX_StorageMoveJournal_DestinationBucket_DestinationObjectName" ON public."StorageMoveJournal" USING btree ("DestinationBucket", "DestinationObjectName");
            CREATE INDEX "IX_StorageMoveJournal_SourceBucket_SourceObjectName" ON public."StorageMoveJournal" USING btree ("SourceBucket", "SourceObjectName");
            CREATE TABLE public."QuarantineUploadIntent" (
              "OperationId" uuid NOT NULL,
              "ParentOperationId" uuid NOT NULL,
              "Bucket" character varying(255) COLLATE "C" NOT NULL,
              "ObjectName" character varying(1024) COLLATE "C" NOT NULL,
              "ContentType" character varying(255) COLLATE "C" NOT NULL,
              "DeclaredSize" bigint NOT NULL,
              "AcknowledgedGeneration" bigint,
              "State" character varying(32) COLLATE "C" NOT NULL,
              "CreatedAt" timestamp with time zone NOT NULL,
              "ModifiedAt" timestamp with time zone NOT NULL,
              CONSTRAINT "PK_QuarantineUploadIntent" PRIMARY KEY ("OperationId"),
              CONSTRAINT "CK_QuarantineUploadIntent_DeclaredSize" CHECK ("DeclaredSize" > 0),
              CONSTRAINT "CK_QuarantineUploadIntent_Generation" CHECK ("AcknowledgedGeneration" IS NULL OR "AcknowledgedGeneration" > 0)
            );
            CREATE INDEX "IX_QuarantineUploadIntent_Bucket_ObjectName" ON public."QuarantineUploadIntent" USING btree ("Bucket", "ObjectName");
            CREATE TABLE public."InstantQuoteUploadSession" (
              "Id" uuid NOT NULL,
              "OwnerSubject" character varying(512) COLLATE "C",
              "IsAuthenticated" boolean NOT NULL,
              "TokenHash" bytea NOT NULL,
              "ExpiresAt" timestamp with time zone NOT NULL,
              "CreatedAt" timestamp with time zone NOT NULL,
              CONSTRAINT "PK_InstantQuoteUploadSession" PRIMARY KEY ("Id"),
              CONSTRAINT "CK_InstantQuoteUploadSession_TokenHash_Length" CHECK (octet_length("TokenHash") = 32)
            );
            CREATE TABLE public."InstantQuoteFinalization" (
              "Id" uuid NOT NULL,
              "SessionId" uuid NOT NULL,
              "IdempotencyKeyHash" bytea NOT NULL,
              "RequestFingerprint" character(64) COLLATE "C" NOT NULL,
              "QuotationRequestId" integer NOT NULL,
              "SelectedFileIds" uuid[] NOT NULL,
              "State" character varying(16) COLLATE "C" NOT NULL,
              "CreatedAt" timestamp with time zone NOT NULL,
              "ModifiedAt" timestamp with time zone NOT NULL,
              CONSTRAINT "PK_InstantQuoteFinalization" PRIMARY KEY ("Id"),
              CONSTRAINT "CK_InstantQuoteFinalization_Fingerprint" CHECK ("RequestFingerprint" ~ '^[0-9a-f]{64}$'),
              CONSTRAINT "CK_InstantQuoteFinalization_KeyHash_Length" CHECK (octet_length("IdempotencyKeyHash") = 32),
              CONSTRAINT "CK_InstantQuoteFinalization_QuotationRequestId_Positive" CHECK ("QuotationRequestId" > 0),
              CONSTRAINT "FK_InstantQuoteFinalization_InstantQuoteUploadSession_SessionId" FOREIGN KEY ("SessionId") REFERENCES public."InstantQuoteUploadSession" ("Id") ON DELETE CASCADE
            );
            CREATE UNIQUE INDEX "IX_InstantQuoteFinalization_SessionId_IdempotencyKeyHash" ON public."InstantQuoteFinalization" USING btree ("SessionId", "IdempotencyKeyHash");
            CREATE TABLE public."InstantQuoteUploadFile" (
              "Id" uuid NOT NULL,
              "SessionId" uuid NOT NULL,
              "IdempotencyKeyHash" bytea NOT NULL,
              "RequestFingerprint" character(64) COLLATE "C" NOT NULL,
              "OriginalFileName" character varying(1024) COLLATE "C" NOT NULL,
              "ValidatedExtension" character varying(16) COLLATE "C" NOT NULL,
              "ValidatedContentType" character varying(255) COLLATE "C" NOT NULL,
              "ExpectedSha256" character(64) COLLATE "C" NOT NULL,
              "ActualSha256" character(64) COLLATE "C",
              "ActualSizeBytes" bigint,
              "GcsGeneration" bigint,
              "TemporaryCleanupCompleted" boolean NOT NULL DEFAULT false,
              "TemporaryBucket" character varying(255) COLLATE "C" NOT NULL,
              "TemporaryObjectName" character varying(1024) COLLATE "C" NOT NULL,
              "FinalBucket" character varying(255) COLLATE "C",
              "FinalObjectName" character varying(1024) COLLATE "C",
              "FinalizedQuotationRequestId" integer,
              "State" character varying(16) COLLATE "C" NOT NULL,
              "CreatedAt" timestamp with time zone NOT NULL,
              "ModifiedAt" timestamp with time zone NOT NULL,
              CONSTRAINT "PK_InstantQuoteUploadFile" PRIMARY KEY ("Id"),
              CONSTRAINT "CK_InstantQuoteUploadFile_ActualSha256" CHECK ("ActualSha256" IS NULL OR "ActualSha256" ~ '^[0-9a-f]{64}$'),
              CONSTRAINT "CK_InstantQuoteUploadFile_ExpectedSha256" CHECK ("ExpectedSha256" ~ '^[0-9a-f]{64}$'),
              CONSTRAINT "CK_InstantQuoteUploadFile_FinalizedQuotationRequestId_Positive" CHECK ("FinalizedQuotationRequestId" IS NULL OR "FinalizedQuotationRequestId" > 0),
              CONSTRAINT "CK_InstantQuoteUploadFile_Fingerprint" CHECK ("RequestFingerprint" ~ '^[0-9a-f]{64}$'),
              CONSTRAINT "CK_InstantQuoteUploadFile_KeyHash_Length" CHECK (octet_length("IdempotencyKeyHash") = 32),
              CONSTRAINT "FK_InstantQuoteUploadFile_InstantQuoteUploadSession_SessionId" FOREIGN KEY ("SessionId") REFERENCES public."InstantQuoteUploadSession" ("Id") ON DELETE CASCADE
            );
            CREATE UNIQUE INDEX "IX_InstantQuoteUploadFile_SessionId_IdempotencyKeyHash" ON public."InstantQuoteUploadFile" USING btree ("SessionId", "IdempotencyKeyHash");
            """,
            "Order" => """
            CREATE TABLE public."OrderDeletionIntent" (
              "OrderId" integer NOT NULL,
              "DeletionId" uuid NOT NULL,
              "RequestedAtUtc" timestamp with time zone NOT NULL,
              "StatusCleanupCompletedAtUtc" timestamp with time zone,
              "CompletedAtUtc" timestamp with time zone,
              "AttemptCount" integer NOT NULL,
              "NextAttemptAtUtc" timestamp with time zone NOT NULL,
              CONSTRAINT "PK_OrderDeletionIntent" PRIMARY KEY ("OrderId"),
              CONSTRAINT "CK_OrderDeletionIntent_AttemptCount" CHECK ("AttemptCount" >= 0)
            );
            CREATE UNIQUE INDEX "IX_OrderDeletionIntent_DeletionId" ON public."OrderDeletionIntent" USING btree ("DeletionId");
            CREATE INDEX "IX_OrderDeletionIntent_PendingDue" ON public."OrderDeletionIntent" USING btree ("NextAttemptAtUtc", "OrderId") WHERE "CompletedAtUtc" IS NULL;
            """,
            _ => throw Invalid(),
        };
    }

    internal static string CollationSql(string database)
    {
        CurrentAppOwnedCollationOperand[] operands = [.. Retained.Where(x => x.Database == database)];
        return operands.Length == 0
            ? throw Invalid()
            : string.Join("\n", operands.Select(x =>
            $"ALTER TABLE {Quote(x.Schema)}.{Quote(x.Table)} ALTER COLUMN {Quote(x.Column)} " +
            $"TYPE {x.PostgreSqlType} COLLATE \"C\";"));
    }

    internal static string[] Databases(CurrentAppOwnedRepairOperation operation)
    {
        return operation switch
        {
            CurrentAppOwnedRepairOperation.CreateEightTables => ["Customer", "Order", "Upload"],
            CurrentAppOwnedRepairOperation.RetainedThirtyOneTextCollations =>
                ["CustomerIdentity", "EmployeeIdentity", "Invoice", "Quotation", "QuotationRequest"],
            _ => throw Invalid(),
        };
    }

    internal static string[] NewTables(string database)
    {
        return database switch
        {
            "Customer" => ["CustomerCreateOperation", "QuotationProfileCompletionOperation"],
            "Order" => ["OrderDeletionIntent"],
            "Upload" => ["StorageMoveJournal", "QuarantineUploadIntent", "InstantQuoteUploadSession",
            "InstantQuoteFinalization", "InstantQuoteUploadFile"],
            _ => throw Invalid(),
        };
    }

    internal static string OperationSha256(CurrentAppOwnedRepairOperation operation)
    {
        string[] databases = Databases(operation);
        string literal = string.Join("\0", databases.Select(database =>
            database + "\0" + (operation == CurrentAppOwnedRepairOperation.CreateEightTables
                ? CreateEightSql(database) : CollationSql(database))));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
            Domain + "\0" + operation + "\0" +
            ApprovedCurrentConsumerSchemaManifest.ServiceContractsSha256 + "\0" +
            ApprovedCurrentConsumerSchemaManifest.RetainedCollationReviewSha256 + "\0" + literal)))
            .ToLowerInvariant();
    }

    internal static void RequireSchemaPair(FreshSchemaPlan before, FreshSchemaPlan after, DateTimeOffset now)
    {
        ProductionSchemaCatalogInspector.ValidatePlan(before, now);
        ProductionSchemaCatalogInspector.ValidatePlan(after, now);
        if (!ApprovedConsumerOverlaySelection.IsApproved(before) ||
            !ApprovedConsumerOverlaySelection.IsApproved(after) ||
            before.SourceCommitSha != after.SourceCommitSha ||
            before.Databases.Sum(x => x.Tables.Count) != 100 ||
            after.Databases.Sum(x => x.Tables.Count) != 100 ||
            before.Databases.Any(x => x.TargetExtensionProfile !=
                ApprovedConsumerOverlaySelection.ProfileForDatabase(x.Database, ConsumerOverlaySelection.CurrentConsumerColumnsV1)) ||
            after.Databases.Any(x => x.TargetExtensionProfile !=
                ApprovedConsumerOverlaySelection.ProfileForDatabase(x.Database, ConsumerOverlaySelection.CurrentConsumerSchemaV2)))
        { throw Invalid(); }
        foreach ((DatabaseSchemaPlan oldDatabase, DatabaseSchemaPlan newDatabase) in before.Databases.Zip(after.Databases))
        {
            if (oldDatabase.Database != newDatabase.Database ||
                oldDatabase.SourceSchemaSha256 != newDatabase.SourceSchemaSha256 ||
                oldDatabase.SourceDispositionProfile != newDatabase.SourceDispositionProfile ||
                JsonSerializer.Serialize(oldDatabase.SourceTableDispositions) != JsonSerializer.Serialize(newDatabase.SourceTableDispositions) ||
                JsonSerializer.Serialize(oldDatabase.Tables) != JsonSerializer.Serialize(newDatabase.Tables))
            { throw Invalid(); }
        }
    }

    private static string Quote(string value)
    {
        return PostgreSqlShadowTarget.QuoteIdentifier(value);
    }

    private static MigrationExecutionException Invalid()
    {
        return new("current_app_owned_repair_closed_scope_invalid", "The additive repair scope is not the reviewed fixed operation.");
    }
}
SET XACT_ABORT ON;
BEGIN TRANSACTION;

IF OBJECT_ID(N'[dbo].[GoogleAnalyticsOutbox]', N'U') IS NULL
BEGIN
    CREATE TABLE [dbo].[GoogleAnalyticsOutbox]
    (
        [ID] BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT [PK_GoogleAnalyticsOutbox] PRIMARY KEY,
        [QuotationID] INT NOT NULL,
        [EventKey] NVARCHAR(128) NOT NULL,
        [EventName] NVARCHAR(40) NOT NULL,
        [ClientId] NVARCHAR(128) NOT NULL,
        [SessionId] NVARCHAR(128) NOT NULL,
        [UserId] NVARCHAR(128) NULL,
        [Currency] VARCHAR(3) NOT NULL,
        [Value] DECIMAL(18,2) NOT NULL,
        [OccurredUtc] DATETIME2 NOT NULL,
        [AttemptCount] INT NOT NULL CONSTRAINT [DF_GoogleAnalyticsOutbox_AttemptCount] DEFAULT (0),
        [NextAttemptUtc] DATETIME2 NOT NULL,
        [LeaseToken] UNIQUEIDENTIFIER NULL,
        [LeaseUntilUtc] DATETIME2 NULL,
        [SentUtc] DATETIME2 NULL,
        [FailedUtc] DATETIME2 NULL,
        [LastError] NVARCHAR(1024) NULL,
        CONSTRAINT [FK_GoogleAnalyticsOutbox_Quotation] FOREIGN KEY ([QuotationID]) REFERENCES [dbo].[Quotation] ([ID])
    );

    CREATE UNIQUE INDEX [UX_GoogleAnalyticsOutbox_EventKey]
        ON [dbo].[GoogleAnalyticsOutbox] ([EventKey]);
    CREATE INDEX [IX_GoogleAnalyticsOutbox_QuotationID]
        ON [dbo].[GoogleAnalyticsOutbox] ([QuotationID]);
    CREATE INDEX [IX_GoogleAnalyticsOutbox_Due]
        ON [dbo].[GoogleAnalyticsOutbox] ([SentUtc], [FailedUtc], [NextAttemptUtc], [LeaseUntilUtc]);
END;

COMMIT TRANSACTION;

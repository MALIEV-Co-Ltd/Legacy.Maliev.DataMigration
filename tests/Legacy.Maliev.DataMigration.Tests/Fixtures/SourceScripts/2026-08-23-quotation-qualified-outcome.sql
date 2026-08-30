SET XACT_ABORT ON;
SET ANSI_NULLS ON;
SET ANSI_PADDING ON;
SET ANSI_WARNINGS ON;
SET ARITHABORT ON;
SET CONCAT_NULL_YIELDS_NULL ON;
SET QUOTED_IDENTIFIER ON;
SET NUMERIC_ROUNDABORT OFF;
BEGIN TRANSACTION;

IF COL_LENGTH(N'[dbo].[Quotation]', N'SourceRequestID') IS NULL
    ALTER TABLE [dbo].[Quotation] ADD [SourceRequestID] INT NULL;

IF COL_LENGTH(N'[dbo].[Quotation]', N'SourceJourneyID') IS NULL
    ALTER TABLE [dbo].[Quotation] ADD [SourceJourneyID] UNIQUEIDENTIFIER NULL;

IF COL_LENGTH(N'[dbo].[Quotation]', N'AcceptedUtc') IS NULL
    ALTER TABLE [dbo].[Quotation] ADD [AcceptedUtc] DATETIME2 NULL;

IF COL_LENGTH(N'[dbo].[Quotation]', N'AcceptanceOrigin') IS NULL
    ALTER TABLE [dbo].[Quotation] ADD [AcceptanceOrigin] VARCHAR(16) NULL;

IF OBJECT_ID(N'[dbo].[QuotationOutcomeOutbox]', N'U') IS NULL
BEGIN
    CREATE TABLE [dbo].[QuotationOutcomeOutbox]
    (
        [ID] BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT [PK_QuotationOutcomeOutbox] PRIMARY KEY,
        [EventKey] NVARCHAR(128) NOT NULL,
        [QuotationID] INT NOT NULL,
        [SourceRequestID] INT NULL,
        [SourceJourneyID] UNIQUEIDENTIFIER NULL,
        [AcceptedUtc] DATETIME2 NOT NULL,
        [AcceptanceOrigin] VARCHAR(16) NOT NULL,
        CONSTRAINT [UQ_QuotationOutcomeOutbox_EventKey] UNIQUE ([EventKey])
    );
END;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE [name] = N'IX_Quotation_SourceRequestID' AND [object_id] = OBJECT_ID(N'[dbo].[Quotation]'))
    EXEC(N'CREATE INDEX [IX_Quotation_SourceRequestID]
        ON [dbo].[Quotation] ([SourceRequestID])
        WHERE [SourceRequestID] IS NOT NULL;');

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE [name] = N'IX_Quotation_SourceJourneyID' AND [object_id] = OBJECT_ID(N'[dbo].[Quotation]'))
    EXEC(N'CREATE INDEX [IX_Quotation_SourceJourneyID]
        ON [dbo].[Quotation] ([SourceJourneyID])
        WHERE [SourceJourneyID] IS NOT NULL;');

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE [name] = N'IX_QuotationOutcomeOutbox_QuotationID' AND [object_id] = OBJECT_ID(N'[dbo].[QuotationOutcomeOutbox]'))
    CREATE INDEX [IX_QuotationOutcomeOutbox_QuotationID] ON [dbo].[QuotationOutcomeOutbox] ([QuotationID]);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE [name] = N'IX_QuotationOutcomeOutbox_SourceRequestID' AND [object_id] = OBJECT_ID(N'[dbo].[QuotationOutcomeOutbox]'))
    CREATE INDEX [IX_QuotationOutcomeOutbox_SourceRequestID] ON [dbo].[QuotationOutcomeOutbox] ([SourceRequestID]) WHERE [SourceRequestID] IS NOT NULL;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE [name] = N'IX_QuotationOutcomeOutbox_SourceJourneyID' AND [object_id] = OBJECT_ID(N'[dbo].[QuotationOutcomeOutbox]'))
    CREATE INDEX [IX_QuotationOutcomeOutbox_SourceJourneyID] ON [dbo].[QuotationOutcomeOutbox] ([SourceJourneyID]) WHERE [SourceJourneyID] IS NOT NULL;

COMMIT TRANSACTION;

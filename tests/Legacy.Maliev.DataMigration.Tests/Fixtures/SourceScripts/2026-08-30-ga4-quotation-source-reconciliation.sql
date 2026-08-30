SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
BEGIN TRANSACTION;

IF OBJECT_ID(N'dbo.GoogleAnalyticsOutbox', N'U') IS NULL
    THROW 51000, 'dbo.GoogleAnalyticsOutbox does not exist; source reconciliation migration cannot continue.', 1;

IF COL_LENGTH(N'dbo.GoogleAnalyticsOutbox', N'SourceRequestID') IS NULL
    ALTER TABLE [dbo].[GoogleAnalyticsOutbox] ADD [SourceRequestID] INT NULL;

IF COL_LENGTH(N'dbo.GoogleAnalyticsOutbox', N'SourceJourneyID') IS NULL
    ALTER TABLE [dbo].[GoogleAnalyticsOutbox] ADD [SourceJourneyID] UNIQUEIDENTIFIER NULL;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE [name] = N'IX_GoogleAnalyticsOutbox_SourceRequestID' AND [object_id] = OBJECT_ID(N'[dbo].[GoogleAnalyticsOutbox]'))
    EXEC(N'CREATE INDEX [IX_GoogleAnalyticsOutbox_SourceRequestID] ON [dbo].[GoogleAnalyticsOutbox] ([SourceRequestID]) WHERE [SourceRequestID] IS NOT NULL;');

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE [name] = N'IX_GoogleAnalyticsOutbox_SourceJourneyID' AND [object_id] = OBJECT_ID(N'[dbo].[GoogleAnalyticsOutbox]'))
    EXEC(N'CREATE INDEX [IX_GoogleAnalyticsOutbox_SourceJourneyID] ON [dbo].[GoogleAnalyticsOutbox] ([SourceJourneyID]) WHERE [SourceJourneyID] IS NOT NULL;');

COMMIT TRANSACTION;

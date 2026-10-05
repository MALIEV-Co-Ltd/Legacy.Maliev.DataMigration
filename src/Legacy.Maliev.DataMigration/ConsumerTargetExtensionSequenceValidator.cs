using Npgsql;

namespace Legacy.Maliev.DataMigration;

/// <summary>Read-only definition admission for the immutable Customer create receipt identity.</summary>
internal static class ConsumerTargetExtensionSequenceValidator
{
    internal static async Task ValidateAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        DatabaseSchemaPlan schema, CancellationToken cancellationToken)
    {
        if (schema.Database != "CustomerIdentity" ||
            schema.TargetExtensionProfile is not (ApprovedTargetExtensionManifest.AuthCustomerCreateAuthorityV1 or ApprovedConsumerColumnOverlayManifest.CustomerV2 or ApprovedCurrentConsumerSchemaManifest.CustomerIdentity))
        {
            return;
        }

        const string sql = """
            SELECT a.attidentity::text, a.atttypid = 'bigint'::regtype,
                sequence.relkind::text, sequence_ns.nspname,
                q.seqtypid = 'bigint'::regtype, q.seqstart, q.seqincrement, q.seqmin, q.seqmax,
                q.seqcache, q.seqcycle,
                sequence.oid = pg_get_serial_sequence(format('%I.%I', n.nspname, t.relname), a.attname)::regclass,
                (SELECT count(*) FROM pg_depend all_owners
                    WHERE all_owners.classid='pg_class'::regclass AND all_owners.objid=sequence.oid
                    AND all_owners.objsubid=0 AND all_owners.refclassid='pg_class'::regclass
                    AND all_owners.deptype='i')
            FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace
            JOIN pg_attribute a ON a.attrelid=t.oid AND a.attname='Id' AND NOT a.attisdropped
            LEFT JOIN pg_depend owner ON owner.classid='pg_class'::regclass AND owner.objsubid=0
                AND owner.refclassid='pg_class'::regclass AND owner.refobjid=t.oid
                AND owner.refobjsubid=a.attnum AND owner.deptype='i'
            LEFT JOIN pg_class sequence ON sequence.oid=owner.objid
            LEFT JOIN pg_namespace sequence_ns ON sequence_ns.oid=sequence.relnamespace
            LEFT JOIN pg_sequence q ON q.seqrelid=sequence.oid
            WHERE n.nspname='public' AND t.relname='CustomerIdentityCreateOperations' AND t.relkind='r';
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) { throw Invalid(); }
        for (int index = 0; index < reader.FieldCount; index++)
        {
            if (reader.IsDBNull(index)) { throw Invalid(); }
        }
        if (reader.GetString(0) != "d" || !reader.GetBoolean(1) || reader.GetString(2) != "S" ||
            reader.GetString(3) != "public" || !reader.GetBoolean(4) || reader.GetInt64(5) != 1 ||
            reader.GetInt64(6) != 1 || reader.GetInt64(7) != 1 || reader.GetInt64(8) != long.MaxValue ||
            reader.GetInt64(9) != 1 || reader.GetBoolean(10) || !reader.GetBoolean(11) || reader.GetInt64(12) != 1 ||
            await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            throw Invalid();
        }
    }

    private static MigrationExecutionException Invalid()
    {
        return new("target_extension_sequence_definition_invalid",
        "The approved target extension identity sequence definition is not valid.");
    }
}

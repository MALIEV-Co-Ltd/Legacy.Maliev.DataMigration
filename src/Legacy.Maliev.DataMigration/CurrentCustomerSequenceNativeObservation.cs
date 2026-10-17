using Npgsql;

namespace Legacy.Maliev.DataMigration;

/// <summary>Read-only exact fixed sequence definition/state and whole database observation; no allocation calls.</summary>
internal static class CurrentCustomerSequenceNativeObservation
{
    internal static async Task<CurrentCustomerSequenceObservation> CaptureAsync(NpgsqlConnection connection, NpgsqlTransaction tx, CancellationToken token)
    {
        if (connection.Database != "Customer" || tx.Connection != connection ||
            tx.IsolationLevel is not (System.Data.IsolationLevel.RepeatableRead or System.Data.IsolationLevel.Serializable))
        { throw Invalid(); }
        const string sql = """
            SELECT t.oid::bigint,a.attnum,s.oid::bigint,s.relfilenode::bigint,pg_get_userbyid(s.relowner),
              format_type(a.atttypid,a.atttypmod),a.attidentity::text,format_type(q.seqtypid,NULL),
              (SELECT d.deptype::text FROM pg_depend d WHERE d.classid='pg_class'::regclass AND d.objid=s.oid
                AND d.refclassid='pg_class'::regclass AND d.refobjid=t.oid AND d.refobjsubid=a.attnum),
              (SELECT count(*) FROM pg_depend d WHERE d.classid='pg_class'::regclass AND d.objid=s.oid
                AND d.refclassid='pg_class'::regclass AND d.refobjsubid>0),
              q.seqstart,q.seqincrement,q.seqmin,q.seqmax,q.seqcache,q.seqcycle,v.last_value,v.is_called,v.log_cnt,
              encode(sha256(convert_to((to_jsonb(q)-'seqstart')::text,'UTF8')),'hex'),
              encode(sha256(convert_to((to_jsonb(s)-'relfilenode')::text,'UTF8')),'hex'),
              encode(sha256(convert_to(to_jsonb(q)::text,'UTF8')),'hex'),
              encode(sha256(convert_to(to_jsonb(s)::text,'UTF8')),'hex')
            FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace
            JOIN pg_attribute a ON a.attrelid=t.oid AND a.attname='ID' AND NOT a.attisdropped
            JOIN pg_class s ON s.oid='public."Customer_ID_seq"'::regclass
            JOIN pg_sequence q ON q.seqrelid=s.oid CROSS JOIN public."Customer_ID_seq" v
            WHERE n.nspname='public' AND t.relname='Customer';
            """;
        CurrentCustomerSequenceState state;
        await using (var command = new NpgsqlCommand(sql, connection, tx) { CommandTimeout = 30 })
        await using (NpgsqlDataReader reader = await command.ExecuteReaderAsync(token))
        {
            if (!await reader.ReadAsync(token).ConfigureAwait(false)) { throw Invalid(); }
            state = new("Customer", "public", "Customer", "ID", "Customer_ID_seq", reader.GetString(4),
                checked((uint)reader.GetInt64(0)), reader.GetInt16(1), checked((uint)reader.GetInt64(2)), checked((uint)reader.GetInt64(3)),
                reader.GetString(5), reader.GetString(6), reader.GetString(7), reader.GetString(8), checked((int)reader.GetInt64(9)),
                reader.GetInt64(10), reader.GetInt64(11), reader.GetInt64(12), reader.GetInt64(13), reader.GetInt64(14), reader.GetBoolean(15),
                reader.GetInt64(16), reader.GetBoolean(17), reader.GetInt64(18), reader.GetString(19), reader.GetString(20), reader.GetString(21), reader.GetString(22));
            if (await reader.ReadAsync(token).ConfigureAwait(false)) { throw Invalid(); }
        }
        return new(state, await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, tx, token));
    }

    internal static Task<string> RequireOperandOwnerAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        CurrentCustomerSequenceRepairScope scope, CurrentCustomerSequenceObservation observation, CancellationToken cancellationToken)
    {
        CurrentCustomerSequenceRepairPermit.RequireOwnerPolicy(scope);
        return CurrentRepairOperandOwnerProfile.RequireNativeAsync(connection, transaction,
            CurrentRepairOperandOwnerPurpose.CustomerSequenceStart, scope.Target, observation.Snapshot, cancellationToken);
    }

    private static MigrationExecutionException Invalid()
    {
        return new("current_customer_sequence_native_observation_invalid", "Exact Customer sequence native observation failed.");
    }
}

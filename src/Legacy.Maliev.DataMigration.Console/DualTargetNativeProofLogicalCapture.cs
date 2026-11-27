using System.Data;
using System.Security.Cryptography;
using System.Text;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal static class DualTargetNativeProofLogicalCapture
{
    internal static async Task<DualTargetNativeProofDatabase> ReadAsync(NpgsqlConnection connection, NpgsqlTransaction tx,
        DualTargetNativeProofTools tools, string privateConnection, string database, string snapshot, CancellationToken ct)
    {
        await ExecuteAsync(connection, tx, "SET LOCAL search_path=pg_catalog;", ct).ConfigureAwait(false);
        await using (var unsupported = new NpgsqlCommand("""
            SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%'
              AND n.nspname NOT LIKE 'pg_temp_%' AND c.relkind='f';
            """, connection, tx))
        { if (Convert.ToInt64(await unsupported.ExecuteScalarAsync(ct).ConfigureAwait(false), System.Globalization.CultureInfo.InvariantCulture) != 0) { throw DualTargetNativeProofPreimage.Invalid(); } }
        using var definition = new HashOnlyStream();
        await tools.DumpAsync(privateConnection, database, snapshot, definition, definition: true, ct).ConfigureAwait(false);
        string schemaHash = definition.Finish();
        string databaseMetadata = await ScalarAsync(connection, tx, """
            SELECT jsonb_build_array(d.datname,pg_get_userbyid(d.datdba),pg_encoding_to_char(d.encoding),d.datlocprovider,
              d.datcollate,d.datctype,to_jsonb(d)->>'datlocale',to_jsonb(d)->>'daticurules',d.datcollversion,
              pg_database_collation_actual_version(d.oid),d.datconnlimit,d.datistemplate,d.datallowconn,t.spcname,d.datacl IS NULL,
              (SELECT coalesce(jsonb_agg(jsonb_build_array(pg_get_userbyid(a.grantor),CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,
                a.privilege_type,a.is_grantable) ORDER BY a.grantor::regrole::text,a.grantee::regrole::text,a.privilege_type,a.is_grantable),'[]') FROM aclexplode(d.datacl) a))::text
            FROM pg_database d JOIN pg_tablespace t ON t.oid=d.dattablespace WHERE d.datname=current_database();
            """, ct).ConfigureAwait(false);
        string collations = await ScalarAsync(connection, tx, """
            SELECT coalesce(jsonb_agg(jsonb_build_array(n.nspname,c.collname,pg_get_userbyid(c.collowner),c.collprovider,c.collisdeterministic,
                c.collencoding,c.collcollate,c.collctype,to_jsonb(c)->>'colllocale',to_jsonb(c)->>'collicurules',c.collversion,pg_collation_actual_version(c.oid))
                ORDER BY n.nspname,c.collname,c.collencoding),'[]')::text FROM pg_collation c JOIN pg_namespace n ON n.oid=c.collnamespace;
            """, ct).ConfigureAwait(false);
        // pg_dump omits extension member definitions; bind exact extension versions as well.
        string extensions = await ScalarAsync(connection, tx, """
            SELECT coalesce(jsonb_agg(jsonb_build_array(e.extname,e.extversion,n.nspname,pg_get_userbyid(e.extowner),e.extrelocatable,
                (SELECT coalesce(jsonb_agg(x::regclass::text ORDER BY x::regclass::text),'[]') FROM unnest(e.extconfig) x),e.extcondition)
                ORDER BY e.extname),'[]')::text FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace;
            """, ct).ConfigureAwait(false);
        var tables = new Dictionary<string, DualTargetNativeProofRows>(StringComparer.Ordinal);
        var names = new List<(string Schema, string Name)>();
        await using (var command = new NpgsqlCommand("""
            SELECT n.nspname,c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%'
              AND n.nspname NOT LIKE 'pg_temp_%' AND c.relkind IN ('r','p','m') ORDER BY n.nspname,c.relname;
            """, connection, tx))
        await using (var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false))
        { while (await reader.ReadAsync(ct).ConfigureAwait(false)) { names.Add((reader.GetString(0), reader.GetString(1))); } }
        foreach (var (Schema, Name) in names)
        {
            tables.Add(Qualified(Schema, Name), await RowsAsync(connection, tx,
                "SELECT encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') AS h FROM " + Qualified(Schema, Name) + " r ORDER BY h;", ct).ConfigureAwait(false));
        }
        // LO OIDs are archive identities; pg_restore preserves them. Only digests leave the database.
        tables.Add("$largeobjects", await RowsAsync(connection, tx,
            "SELECT encode(sha256(convert_to(jsonb_build_array(loid,pageno,encode(data,'hex'))::text,'UTF8')),'hex') AS h FROM pg_largeobject ORDER BY h;", ct).ConfigureAwait(false));
        tables.Add("$largeobjectowners", await RowsAsync(connection, tx,
            "SELECT encode(sha256(convert_to(jsonb_build_array(oid,pg_get_userbyid(lomowner),lomacl::text)::text,'UTF8')),'hex') AS h FROM pg_largeobject_metadata ORDER BY h;", ct).ConfigureAwait(false));
        var sequences = new Dictionary<string, DualTargetNativeProofSequence>(StringComparer.Ordinal);
        var definitions = new List<(string Schema, string Name, string Type, long Start, long Increment, long Minimum, long Maximum, long Cache, bool Cycle)>();
        await using (var command = new NpgsqlCommand("""
            SELECT n.nspname,c.relname,format_type(s.seqtypid,NULL),s.seqstart,s.seqincrement,s.seqmin,s.seqmax,s.seqcache,s.seqcycle
            FROM pg_sequence s JOIN pg_class c ON c.oid=s.seqrelid JOIN pg_namespace n ON n.oid=c.relnamespace ORDER BY n.nspname,c.relname;
            """, connection, tx))
        await using (var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false))
        { while (await reader.ReadAsync(ct).ConfigureAwait(false)) { definitions.Add((reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetInt64(3), reader.GetInt64(4), reader.GetInt64(5), reader.GetInt64(6), reader.GetInt64(7), reader.GetBoolean(8))); } }
        foreach (var sequence in definitions)
        {
            await using var command = new NpgsqlCommand("SELECT last_value,is_called FROM " + Qualified(sequence.Schema, sequence.Name) + ";", connection, tx);
            await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
            if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { throw DualTargetNativeProofPreimage.Invalid(); }
            sequences.Add(Qualified(sequence.Schema, sequence.Name), new(sequence.Type, sequence.Start, sequence.Increment, sequence.Minimum,
                sequence.Maximum, sequence.Cache, sequence.Cycle, reader.GetInt64(0), reader.GetBoolean(1)));
            if (await reader.ReadAsync(ct).ConfigureAwait(false)) { throw DualTargetNativeProofPreimage.Invalid(); }
        }
        return new(database, DualTargetNativeProofPreimage.HashBytes(Encoding.UTF8.GetBytes(schemaHash + "\0" + databaseMetadata + "\0" + collations + "\0" + extensions)), tables, sequences);
    }

    internal static async Task<DualTargetNativeProofRows> RowsAsync(NpgsqlConnection connection, NpgsqlTransaction tx, string fixedQuery, CancellationToken ct)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256); long count = 0;
        await using var command = new NpgsqlCommand(fixedQuery, connection, tx) { CommandTimeout = 60 };
        await using var reader = await command.ExecuteReaderAsync(CommandBehavior.SequentialAccess, ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            string row = reader.GetString(0); if (!DualTargetNativeProofPreimage.IsHash(row)) { throw DualTargetNativeProofPreimage.Invalid(); }
            hash.AppendData(Encoding.ASCII.GetBytes(row)); count = checked(count + 1);
        }
        return new(count, Convert.ToHexStringLower(hash.GetHashAndReset()));
    }
    internal static string Qualified(string schema, string table)
    {
        return Quote(schema) + "." + Quote(table);
    }

    internal static string Quote(string identifier)
    {
        return '"' + identifier.Replace("\"", "\"\"", StringComparison.Ordinal) + '"';
    }

    internal static async Task<string> ScalarAsync(NpgsqlConnection connection, NpgsqlTransaction? tx, string sql, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand(sql, connection, tx) { CommandTimeout = 60 };
        return Convert.ToString(await command.ExecuteScalarAsync(ct).ConfigureAwait(false), System.Globalization.CultureInfo.InvariantCulture) ?? throw DualTargetNativeProofPreimage.Invalid();
    }
    internal static async Task ExecuteAsync(NpgsqlConnection connection, NpgsqlTransaction? tx, string sql, CancellationToken ct)
    { await using var command = new NpgsqlCommand(sql, connection, tx) { CommandTimeout = 60 }; _ = await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false); }

    private sealed class HashOnlyStream : Stream
    {
        private readonly IncrementalHash _hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        internal string Finish()
        {
            return Convert.ToHexStringLower(_hash.GetHashAndReset());
        }

        public override bool CanRead => false; public override bool CanWrite => true; public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException(); public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Write(byte[] buffer, int offset, int count)
        {
            _hash.AppendData(buffer, offset, count);
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) { cancellationToken.ThrowIfCancellationRequested(); _hash.AppendData(buffer.Span); return ValueTask.CompletedTask; }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        protected override void Dispose(bool disposing) { if (disposing) { _hash.Dispose(); } base.Dispose(disposing); }
    }
}

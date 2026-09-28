BEGIN;
DO $repair$
DECLARE
  table_name text;
  column_name text;
  actual_default text;
  tables text[];
BEGIN
  IF current_database() = 'Customer' THEN
    tables := ARRAY['Address','Company','Customer','CustomerFiles','NdaFiles'];
  ELSIF current_database() = 'Employee' THEN
    tables := ARRAY['EmployeeFiles'];
  ELSE
    RAISE EXCEPTION 'unapproved database for default repair';
  END IF;
  FOREACH table_name IN ARRAY tables LOOP
    FOREACH column_name IN ARRAY ARRAY['CreatedDate','ModifiedDate'] LOOP
      SELECT pg_get_expr(d.adbin,d.adrelid) INTO actual_default
      FROM pg_attrdef d
      JOIN pg_attribute a ON a.attrelid=d.adrelid AND a.attnum=d.adnum
      JOIN pg_class c ON c.oid=a.attrelid
      JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='public' AND c.relname=table_name AND a.attname=column_name;
      IF actual_default IS DISTINCT FROM '(CURRENT_TIMESTAMP AT TIME ZONE ''Asia/Bangkok''::text)' THEN
        RAISE EXCEPTION 'default preimage mismatch %.%', table_name, column_name;
      END IF;
      EXECUTE format('ALTER TABLE public.%I ALTER COLUMN %I SET DEFAULT CURRENT_TIMESTAMP',table_name,column_name);
    END LOOP;
  END LOOP;
END;
$repair$;
COMMIT;
-- Read-only RLS Security Audit Queries for PostgreSQL / Supabase

-- 1. Find all tables in public schema WITHOUT Row-Level Security enabled
SELECT
    schemaname,
    tablename,
    rowsecurity AS rls_enabled
FROM pg_tables
WHERE schemaname = 'public'
  AND rowsecurity = false
ORDER BY tablename;

-- 2. Find tables with RLS enabled but ZERO policies (effectively inaccessible or misconfigured)
SELECT
    t.tablename
FROM pg_tables t
LEFT JOIN pg_policies p
    ON t.schemaname = p.schemaname AND t.tablename = p.tablename
WHERE t.schemaname = 'public'
  AND t.rowsecurity = true
  AND p.policyname IS NULL;

-- 3. Inspect existing policies for overly permissive USING (true) rules
SELECT
    schemaname,
    tablename,
    policyname,
    cmd,
    roles,
    qual,
    with_check
FROM pg_policies
WHERE schemaname = 'public'
ORDER BY tablename, policyname;

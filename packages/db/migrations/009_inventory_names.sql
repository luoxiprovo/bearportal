-- Independent, transactional counters retain their value after inventory removal or renaming.
CREATE TABLE inventory_name_counters (
  prefix text PRIMARY KEY CHECK (prefix IN ('s', 'b')),
  value bigint NOT NULL CHECK (value >= 0)
);
DO $$
DECLARE previous_actor text := current_setting('bearportal.actor', true);
BEGIN
PERFORM set_config('bearportal.actor', 'platform_administrator', true);
INSERT INTO inventory_name_counters(prefix,value)
SELECT 's', coalesce(max(substring(label FROM '^s-([0-9]+)$')::bigint),0) FROM servers
UNION ALL
SELECT 'b', coalesce(max(substring(label FROM '^b-([0-9]+)$')::bigint),0) FROM relay_connections;
PERFORM set_config('bearportal.actor', coalesce(previous_actor, ''), true);
END $$;
GRANT SELECT, UPDATE ON inventory_name_counters TO bearportal_app;
ALTER TABLE inventory_name_counters ENABLE ROW LEVEL SECURITY;
ALTER TABLE inventory_name_counters FORCE ROW LEVEL SECURITY;
CREATE POLICY inventory_names_operator ON inventory_name_counters
  USING (bearportal_actor() IN ('platform_administrator', 'infrastructure_operator'))
  WITH CHECK (bearportal_actor() IN ('platform_administrator', 'infrastructure_operator'));

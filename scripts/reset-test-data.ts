import { spawnSync } from 'node:child_process';
import { chmodSync, copyFileSync, existsSync, mkdirSync, readdirSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { createConnection } from 'node:net';
import pg from 'pg';

// Keep operator identities and application configuration; all tenant and inventory records are disposable.
export const CLEAR_TEST_DATA_SQL = `
BEGIN;
SELECT set_config('bearportal.actor','platform_administrator',true);
CREATE TEMP TABLE reset_operator_snapshot ON COMMIT DROP AS
 SELECT u.id,u.identity_subject,u.verified_email,r.role FROM users u JOIN operator_roles r ON r.user_id=u.id;
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM operator_roles r JOIN users u ON u.id=r.user_id WHERE r.revoked_at IS NULL AND u.status='active') THEN RAISE EXCEPTION 'No operator account to preserve'; END IF;
 IF EXISTS(SELECT 1 FROM billing_subscriptions WHERE subscription_id IS NOT NULL AND status <> 'canceled') THEN RAISE EXCEPTION 'Cancel Stripe subscriptions before resetting local billing records'; END IF;
 IF EXISTS(SELECT 1 FROM jobs WHERE state='running') THEN RAISE EXCEPTION 'A job is still running'; END IF;
 IF EXISTS(SELECT 1 FROM onboarding_requests WHERE state='installing') THEN RAISE EXCEPTION 'An installation is still running'; END IF;
END $$;
TRUNCATE TABLE billing_events,billing_subscriptions,cancellation_schedules,restore_requests,upgrade_plans,cleanup_reports,
 audit_events,idempotency_keys,outbox_events,backups,jobs,dns_connections,deployments,
 secret_refs,domains,server_assignments,allocation_requests,invitations,organizations,
 relay_connections,servers,diagnoses,provider_attempts,required_actions,inventory_jobs,
 host_enrollments,host_identities,host_auth_challenges,host_commands,hosting_estimates,
 relay_assignments,dns_observations,dns_plans,health_observations,installer_runs,
 mailboxes,notifications,incidents,approvals,oversight_sessions,operation_steps,onboarding_requests
 RESTART IDENTITY CASCADE;
DELETE FROM identity_accounts WHERE user_id NOT IN(SELECT id FROM reset_operator_snapshot);
DELETE FROM users WHERE id NOT IN(SELECT id FROM reset_operator_snapshot);
UPDATE inventory_name_counters SET value=0;
UPDATE control_plane_state SET mode='normal' WHERE id=1;
DO $$ BEGIN
 IF EXISTS(SELECT * FROM reset_operator_snapshot EXCEPT SELECT u.id,u.identity_subject,u.verified_email,r.role FROM users u JOIN operator_roles r ON r.user_id=u.id)
 THEN RAISE EXCEPTION 'Operator access changed'; END IF;
END $$;
COMMIT;`;

export async function resetTestData(env: Record<string, string>, root: string, args: string[]) {
  if (!args.includes('--confirm-clear-test-data')) throw new Error('This deletes local customers and inventory. Stop BearPortal, then run pnpm reset:test-data --confirm-clear-test-data. Operator access is preserved.');
  if (env.BEARPORTAL_ENV !== 'development' || process.env.BEARPORTAL_ENV === 'production') throw new Error('Test reset requires BEARPORTAL_ENV=development.');
  const database = new URL(env.MIGRATION_DATABASE_URL);
  if (!['127.0.0.1','localhost','[::1]'].includes(database.hostname) || !/^bearportal(?:_test_[a-z0-9_]+)?$/.test(decodeURIComponent(database.pathname.slice(1)))) throw new Error('Test reset only supports a local BearPortal database.');
  if (env.BEARPORTAL_STRIPE_MODE === 'live' || (env.STRIPE_SECRET_KEY && !/^(sk|rk)_test_/.test(env.STRIPE_SECRET_KEY))) {
    throw new Error('Test reset refuses live or unrecognized Stripe credentials. Use Stripe test mode.');
  }
  if (existsSync(join(root,'.data','server-migration-source.lock'))) throw new Error('Reset is blocked by a server migration fence.');
  // Probe the API listener directly: public HTTPS still responds through Caddy when the API is stopped.
  const port=Number(env.PORT || '8088');
  if (!Number.isInteger(port) || port<1 || port>65535) throw new Error('PORT is invalid.');
  const host=env.BEARPORTAL_BIND_HOST || '127.0.0.1';
  if (!['127.0.0.1','::1','localhost','0.0.0.0','::'].includes(host)) throw new Error('Test reset requires a local API bind address.');
  const responding=await new Promise<boolean>((resolve,reject)=>{
    const socket=createConnection({host:host==='::'?'::1':host==='0.0.0.0'?'127.0.0.1':host,port});
    socket.once('connect',()=>{socket.destroy();resolve(true)});
    socket.once('error',(error:NodeJS.ErrnoException)=>{socket.destroy();if(error.code==='ECONNREFUSED')resolve(false);else reject(new Error('Could not verify that the API is stopped.'));});
    socket.setTimeout(2000,()=>{socket.destroy();reject(new Error('Could not verify that the API is stopped.'));});
  });
  if (responding) throw new Error('Stop BearPortal with sudo systemctl stop bearportal-api before resetting data.');
  if (!env.BEARPORTAL_SECRETS_DIR) throw new Error('BEARPORTAL_SECRETS_DIR is required.');
  const secretsDir = env.BEARPORTAL_SECRETS_DIR;
  const files = existsSync(secretsDir) ? readdirSync(secretsDir).filter(name => /^[0-9a-f-]{36}\.bin$/i.test(name)) : [];
  const backup = join(root,'.data','backups',`test-reset-${new Date().toISOString().replace(/[:.]/g,'-')}-${randomUUID().slice(0,8)}`);
  mkdirSync(backup,{recursive:true,mode:0o700});chmodSync(backup,0o700);
  const backupDatabase = new URL(env.BEARPORTAL_BACKUP_DATABASE_URL || env.MIGRATION_DATABASE_URL);
  if (backupDatabase.hostname !== database.hostname || (backupDatabase.port||'5432') !== (database.port||'5432') || backupDatabase.pathname !== database.pathname) throw new Error('Backup connection must target the same database as the reset. No data was cleared.');
  const pgEnv = {...process.env,PGHOST:backupDatabase.hostname,PGPORT:backupDatabase.port||'5432',PGDATABASE:decodeURIComponent(backupDatabase.pathname.slice(1)),PGUSER:decodeURIComponent(backupDatabase.username),PGPASSWORD:decodeURIComponent(backupDatabase.password)};
  // Password stays in the child environment; never put a credential-bearing URL in arguments or errors.
  const dump = join(backup,'database.dump');
  const saved = spawnSync('pg_dump',['--format=custom','--file',dump],{env:pgEnv,stdio:'pipe'});
  if (saved.status !== 0) {
    // FORCE RLS tables require the local cluster administrator for a complete dump.
    const local = database.port === '' || database.port === '5432';
    const fallback = local ? spawnSync('sudo',['-n','-u','postgres','pg_dump','--host=/var/run/postgresql','--port=5432','--dbname='+decodeURIComponent(database.pathname.slice(1)),'--format=custom'],{stdio:['ignore','pipe','pipe'],maxBuffer:256*1024*1024}) : null;
    if (!fallback || fallback.status !== 0) throw new Error('Database backup failed. No data was cleared.');
    writeFileSync(dump,fallback.stdout,{mode:0o600});
  }
  chmodSync(dump,0o600);
  if (spawnSync('pg_restore',['--list',dump],{stdio:'pipe'}).status !== 0) throw new Error('Backup validation failed. No data was cleared.');
  const credentialBackup=join(backup,'encrypted-secrets');mkdirSync(credentialBackup,{mode:0o700});
  for(const name of files){copyFileSync(join(secretsDir,name),join(credentialBackup,name));chmodSync(join(credentialBackup,name),0o600);}
  const client = new pg.Client({connectionString:env.MIGRATION_DATABASE_URL});
  await client.connect();
  try { await client.query(CLEAR_TEST_DATA_SQL); }
  catch { await client.query('ROLLBACK'); throw new Error('Reset failed and was rolled back. Check that Stripe subscriptions are canceled, no installation/job is running, and an active operator exists. Database and credentials are preserved.'); }
  finally { await client.end(); }
  for(const name of files)unlinkSync(join(secretsDir,name));
  const state=join(root,'.data','trial','walk-state.json');if(existsSync(state))unlinkSync(state);
  console.log(`Cleared local customer and inventory data. Operator access, plans, app configuration and SSH keys are preserved. Backup: ${backup}`);
  console.log('Remote servers, DNS, Brevo domains and Google Identity Platform accounts are unchanged. Add fresh resources before retesting.');
}

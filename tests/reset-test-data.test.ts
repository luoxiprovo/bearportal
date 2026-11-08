import { mkdtempSync, mkdirSync, writeFileSync, existsSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { CLEAR_TEST_DATA_SQL, resetTestData } from '../scripts/reset-test-data.ts';
import { migrate } from '../packages/db/src/migrate.ts';
import { integrationDatabases, queryTestDatabase } from './helpers/database.ts';

const {migrationUrl,superDatabaseUrl} = integrationDatabases();
const query=(sql:string)=>queryTestDatabase(sql,superDatabaseUrl);

test('explicit test reset clears inventory and customers while preserving operator identity, role and plans', async()=>{
 await migrate(migrationUrl);
 // Isolated test database only; seed both managed identities and inventory to exercise FK cascades.
 await query('TRUNCATE users,organizations,servers,relay_connections,secret_refs,operator_roles,identity_accounts CASCADE');
 const admin=randomUUID(),customer=randomUUID(),org=randomUUID(),role=randomUUID();
 await query(`INSERT INTO users(id,identity_subject,verified_email,email_verified,status) VALUES
 ('${admin}','reset-admin','operator@example.net',true,'active'),('${customer}','reset-customer','customer@example.net',true,'active');
 INSERT INTO operator_roles(id,user_id,role,reason) VALUES('${role}','${admin}','platform_administrator','test');
 INSERT INTO identity_accounts(issuer,subject,user_id,provider) VALUES('https://identity.example','admin','${admin}','google.com'),('https://identity.example','customer','${customer}','password');
 INSERT INTO organizations(id,owner_user_id,name,status) VALUES('${org}','${customer}','Reset customer','active');
 INSERT INTO domains(id,organization_id,normalized_name,existing_mail,state) VALUES('${randomUUID()}','${org}','reset.example.com',false,'pending');
 INSERT INTO servers(id,label,public_ipv4,profile_code,operator_contact,state) VALUES('${randomUUID()}','reset-server','203.0.113.10','e2-micro','operator@example.net','pending_validation');
 INSERT INTO relay_connections(id,provider,label,provider_account_id,smtp_login,daily_limit,state) VALUES('${randomUUID()}','brevo','reset-brevo','reset-account','smtp@example.net',300,'available');`);
 const plans=await query('SELECT count(*) FROM plans');
 const root=mkdtempSync(join(tmpdir(),'bearportal-reset-test-'));
 const secrets=join(root,'secrets');mkdirSync(secrets);
 const name=randomUUID()+'.bin';writeFileSync(join(secrets,name),'encrypted-test-canary');
 await resetTestData({BEARPORTAL_ENV:'development',MIGRATION_DATABASE_URL:migrationUrl,BEARPORTAL_API_ORIGIN:'http://127.0.0.1:1',BEARPORTAL_SECRETS_DIR:secrets},root,['--confirm-clear-test-data']);
 assert.equal(existsSync(join(secrets,name)),false);
 const backups=join(root,'.data','backups');const backup=join(backups,readdirSync(backups)[0]);
 assert.ok(existsSync(join(backup,'database.dump')));
 assert.equal(readFileSync(join(backup,'encrypted-secrets',name),'utf8'),'encrypted-test-canary');
 assert.deepEqual(await query('SELECT count(*) FROM servers UNION ALL SELECT count(*) FROM relay_connections UNION ALL SELECT count(*) FROM domains UNION ALL SELECT count(*) FROM organizations'),[['0'],['0'],['0'],['0']]);
 assert.deepEqual(await query('SELECT id FROM users'),[[admin]]);
 assert.deepEqual(await query('SELECT id,user_id FROM operator_roles'),[[role,admin]]);
 assert.deepEqual(await query('SELECT subject,user_id FROM identity_accounts'),[['admin',admin]]);
 assert.deepEqual(await query('SELECT count(*) FROM plans'),plans);
 await query(CLEAR_TEST_DATA_SQL); // Repeating an empty reset is safe and keeps operator access.
 assert.deepEqual(await query('SELECT count(*) FROM users'),[['1']]);
});

test('reset refuses unconfirmed and production invocations before any filesystem or database changes',async()=>{
 await assert.rejects(resetTestData({},'/unused',[]),/confirm-clear-test-data/);
 await assert.rejects(resetTestData({BEARPORTAL_ENV:'production'},'/unused',['--confirm-clear-test-data']),/development/);
 await assert.rejects(resetTestData({BEARPORTAL_ENV:'development',MIGRATION_DATABASE_URL:'postgres://example.com/bearportal'},'/unused',['--confirm-clear-test-data']),/local BearPortal database/);
});

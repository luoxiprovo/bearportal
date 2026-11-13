"""Migration safety/restore checks; runs in disposable files and databases only."""
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import uuid
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import server_migration as m

class Base(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='bearportal-migration-test-')
        self.root=Path(self.temp.name)
    def tearDown(self):self.temp.cleanup()
    def stage(self):
        stage=m.private_dir(self.root/'payload')
        m.atomic_write(stage/'config/env','BEARPORTAL_SECRET_KEY='+'ab'*32+'\nSTRIPE_SECRET_KEY=private-canary\n')
        m.atomic_write(stage/'database.dump',b'PGDMP-fake')
        m.write_json(stage/'manifest.json',dict(protocol=1,id=str(uuid.uuid4())))
        return stage

class Files(Base):
    def test_bundle_roundtrip_and_corruption(self):
        stage=self.stage();bundle=self.root/'export.tar.gz';m.pack(stage,bundle)
        result=m.unpack(bundle,self.root/'restored')
        self.assertEqual(result['files']['database.dump']['size'],10)
        self.assertEqual((self.root/'restored/config/env').read_text(),(stage/'config/env').read_text())
        self.assertEqual(bundle.stat().st_mode&0o777,0o600)
        # Repack a changed file without changing its declared hash.
        (stage/'database.dump').write_bytes(b'corrupted')
        bad=self.root/'bad.tar.gz'
        with tarfile.open(bad,'w:gz')as archive:
            for path in stage.rglob('*'):
                if path.is_file():archive.add(path,arcname=path.relative_to(stage))
        with self.assertRaisesRegex(m.MigrationError,'checksum'):m.unpack(bad,self.root/'bad-restore')
    def test_rejects_traversal_symlinks_and_duplicates(self):
        for index,name in enumerate(['../outside','/tmp/outside','config/link','manifest.json']):
            archive=self.root/('unsafe-'+str(index)+'.tar.gz')
            with tarfile.open(archive,'w:gz')as bundle:
                entry=tarfile.TarInfo(name);entry.size=1
                if name=='config/link':entry.type=tarfile.SYMTYPE;entry.linkname='/etc/passwd';entry.size=0;bundle.addfile(entry)
                else:
                    bundle.addfile(entry,io.BytesIO(b'x'))
                    if name=='manifest.json':bundle.addfile(entry,io.BytesIO(b'x'))
            with self.assertRaises(m.MigrationError):m.unpack(archive,self.root/('unpack-'+str(index)))
        self.assertFalse((self.root/'outside').exists())
    def test_env_paths_and_encryption_key_preserved(self):
        source=dict(BEARPORTAL_SECRET_KEY='cd'*32,STRIPE_SECRET_KEY='private-canary',BEARPORTAL_IDENTITY_PROJECT_ID='same-project',DATABASE_URL='old',MIGRATION_DATABASE_URL='old')
        meta=dict(database='bearportal',app_role='bearportal_app',owner_role='bearportal')
        target=m.target_env(source,'/opt/new-app',meta,dict(app='newapp',owner='newowner'))
        self.assertEqual(target['BEARPORTAL_SECRET_KEY'],source['BEARPORTAL_SECRET_KEY'])
        self.assertEqual(target['STRIPE_SECRET_KEY'],source['STRIPE_SECRET_KEY'])
        self.assertEqual(target['BEARPORTAL_SECRETS_DIR'],'/opt/new-app/.data/trial/secrets')
        self.assertEqual(m.parse_env(m.render_env(target)),target)
        self.assertIn('newapp@127.0.0.1',target['DATABASE_URL'])
        for invalid in ['export NAME=value','NAME=one\nNAME=two','NAME="line\\nvalue"']:
            with self.assertRaises(m.MigrationError):m.parse_env(invalid)
    def test_proxy_keeps_other_sites_and_verifies_target_tls(self):
        other=dict(match=[dict(host=['other.example'])],handle=[dict(handler='static_response',body='unchanged')])
        own=dict(match=[dict(host=['app.example'])],handle=[dict(handler='reverse_proxy')])
        config=dict(apps=dict(http=dict(servers=dict(main=dict(routes=[own,other])))))
        result=m.forwarding_config(config,'app.example','8.8.8.8')
        handler=result['apps']['http']['servers']['main']['routes'][0]['handle'][0]
        self.assertEqual(handler['transport']['tls']['server_name'],'app.example')
        self.assertEqual(handler['upstreams'][0]['dial'],'8.8.8.8:443')
        self.assertEqual(other['handle'][0]['body'],'unchanged')
        target=m.target_caddy_config('app.example','8.8.4.4',8088)
        self.assertIn('trusted_proxies static 8.8.4.4/32',target)
        self.assertIn('header_up X-Forwarded-For {client_ip}',target)
        self.assertNotIn('tls_insecure_skip_verify',target)
    def test_no_secrets_in_service_and_no_injection(self):
        unit=m.service_unit('/opt/bearportal','bearportal',Path('/opt/node/bin'))
        self.assertIn('EnvironmentFile=/opt/bearportal/.data/trial/env',unit)
        self.assertNotIn('BEARPORTAL_SECRET_KEY=',unit)
        for value in ['/opt/app\nExecStart=/bin/evil','/opt/app with spaces']:
            with self.assertRaises(m.MigrationError):m.service_unit(value,'bearportal',Path('/opt/node/bin'))
        with self.assertRaises(m.MigrationError):m.identifier('bad;DROP DATABASE postgres')
    def test_command_failure_does_not_log_private_input(self):
        canary=b'postgres://secret-password@host/db'
        with patch.object(subprocess,'run',return_value=subprocess.CompletedProcess([],1,b'',canary)):
            with self.assertRaises(m.MigrationError)as error:m.run(['psql'],data=canary)
        self.assertNotIn('secret-password',str(error.exception))
    def test_snapshot_difference_is_rejected(self):
        with self.assertRaises(m.MigrationError):m.compare_snapshot({'users':dict(count=2,rls=True,force_rls=True)},{'users':dict(count=1,rls=True,force_rls=True)})
    def test_rollback_cannot_resume_stale_source_after_handoff(self):
        root=self.root/'old';m.private_dir(root/'.data');m.write_json(root/m.FENCE_NAME,dict(role='source',id=str(uuid.uuid4()),phase='forwarding'))
        with self.assertRaisesRegex(m.MigrationError,'lose new writes'):m.rollback_source(root,True)
        self.assertTrue((root/m.FENCE_NAME).exists())
        with self.assertRaisesRegex(m.MigrationError,'confirm-target-stopped'):m.rollback_source(root,False)
    def test_code_bundle_is_portable(self):
        repo=self.root/'repo';repo.mkdir()
        env={**os.environ,'GIT_CONFIG_NOSYSTEM':'1'}
        def git(*args):return subprocess.run(['git',*args],cwd=repo,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
        git('init','-b','main');(repo/'app.txt').write_text('tracked code')
        git('add','.');git('-c','user.name=Migration Test','-c','user.email=test@example.org','commit','-m','fixture')
        bundle=self.root/'code.bundle';m.create_git_bundle(repo,bundle,'main')
        clone=self.root/'clone';subprocess.run(['git','clone','--branch','main',str(bundle),str(clone)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
        self.assertEqual((clone/'app.txt').read_text(),'tracked code')

class Export(Base):
    def prepare_export(self):
        root=self.root/'old';root.mkdir();m.private_dir(root/'.data')
        envfile=root/'.data/env';m.atomic_write(envfile,'PRIVATE=canary\n')
        public=root/'public.pem';public.write_text('public fixture')
        secret_dir=m.private_dir(root/'secrets');m.atomic_write(secret_dir/(str(uuid.uuid4())+'.bin'),b'encrypted-fixture')
        meta=dict(protocol=1,id=str(uuid.uuid4()),source_root=str(root),source_env=str(envfile),hostname='app.example',source_ip='8.8.8.8',branch='main',mail_servers=[],fenced=False,service_enabled=True)
        env=dict(BEARPORTAL_JWT_PUBLIC_KEY_FILE=str(public),BEARPORTAL_SECRETS_DIR=str(secret_dir))
        spec=dict(database='fixture',port=5432,app_role='fixture_app')
        events=[]
        def command(args,**kwargs):
            events.append([str(a)for a in args])
            if kwargs.get('output')is not None:kwargs['output'].write(b'fixture')
            return b''
        return root,meta,env,spec,events,command
    def test_failure_before_stop_unfences_source(self):
        root,meta,env,spec,events,command=self.prepare_export()
        with patch.object(m,'STATE_ROOT',self.root/'state'),patch.object(m,'source_inspect',return_value=(meta,env,spec)),patch.object(m,'wait_drained',side_effect=m.MigrationError('active job')),patch.object(m,'run',side_effect=command):
            with self.assertRaises(m.MigrationError):m.export_bundle(root,self.root/'bundle.tgz')
        self.assertFalse((root/m.FENCE_NAME).exists());self.assertFalse(any('stop'in e for e in events))
    def test_failure_after_stop_stays_fenced(self):
        root,meta,env,spec,events,command=self.prepare_export()
        with patch.object(m,'STATE_ROOT',self.root/'state'),patch.object(m,'source_inspect',return_value=(meta,env,spec)),patch.object(m,'wait_drained'),patch.object(m,'service_value',return_value='inactive'),patch.object(m,'snapshot',side_effect=m.MigrationError('dump failed')),patch.object(m,'run',side_effect=command):
            with self.assertRaises(m.MigrationError):m.export_bundle(root,self.root/'bundle.tgz')
        self.assertEqual(m.read_json(root/m.FENCE_NAME)['phase'],'export_failed')
        self.assertIn(['systemctl','stop',m.SERVICE],events);self.assertNotIn(['systemctl','start',m.SERVICE],events)
    def test_successful_export_keeps_source_stopped_and_bundle_private(self):
        root,meta,env,spec,events,command=self.prepare_export()
        def bundle(_root,path,_branch):m.atomic_write(path,b'gitfixture')
        with patch.object(m,'STATE_ROOT',self.root/'state'),patch.object(m,'source_inspect',return_value=(meta,env,spec)),patch.object(m,'wait_drained'),patch.object(m,'service_value',return_value='inactive'),patch.object(m,'snapshot',return_value={}),patch.object(m,'rows',return_value=[]),patch.object(m,'copy_tls'),patch.object(m,'copy_ssh'),patch.object(m,'create_git_bundle',side_effect=bundle),patch.object(m,'run',side_effect=command),patch.dict(os.environ,{},clear=True):
            result=m.export_bundle(root,self.root/'bundle.tgz')
        self.assertEqual(m.read_json(root/m.FENCE_NAME)['phase'],'exported')
        self.assertEqual(m.file_hash(self.root/'bundle.tgz'),result['sha256'])
        restored=m.unpack(self.root/'bundle.tgz',self.root/'restored-export')
        self.assertIn('config/env',restored['files']);self.assertNotIn('canary',json.dumps(restored))
        self.assertNotIn(['systemctl','start',m.SERVICE],events)

class Database(Base):
    @unittest.skipUnless(os.environ.get('BEARPORTAL_TEST_USE_LOCAL_PSQL')=='1','Local PostgreSQL administrator test not configured')
    def test_real_postgres_custom_archive_preserves_rows_rls_owner_and_grants(self):
        # Extra databases are disposable and never named like production.
        source='bearportal_test_migsrc_'+uuid.uuid4().hex[:16]
        target='bearportal_test_migdst_'+uuid.uuid4().hex[:16]
        try:
            m.sql('CREATE DATABASE '+m.identifier(source)+' OWNER bearportal; CREATE DATABASE '+m.identifier(target)+' OWNER bearportal;')
            m.sql("SET ROLE bearportal; CREATE TABLE migration_fixture(id integer PRIMARY KEY,value text); ALTER TABLE migration_fixture ENABLE ROW LEVEL SECURITY; ALTER TABLE migration_fixture FORCE ROW LEVEL SECURITY; CREATE POLICY deny_all ON migration_fixture USING(false); GRANT SELECT ON migration_fixture TO bearportal_app; RESET ROLE; INSERT INTO migration_fixture VALUES(1,'synthetic-data');",source)
            snapshot=m.snapshot(source)
            dump=self.root/'database.dump'
            with dump.open('wb')as stream:m.run(m.pg_command('pg_dump',source)+['--format=custom'],output=stream,env=m.pg_env())
            m.restore_database(dict(database=target,owner_role='bearportal',app_role='bearportal_app',snapshot=snapshot),dump)
            self.assertEqual(m.sql('SELECT value FROM migration_fixture',target),'synthetic-data')
            self.assertEqual(m.sql("SELECT tableowner FROM pg_tables WHERE tablename='migration_fixture'",target),'bearportal')
            self.assertEqual(m.sql("SELECT has_table_privilege('bearportal_app','migration_fixture','SELECT')",target),'t')
            self.assertEqual(m.sql('SET ROLE bearportal_app; SELECT count(*) FROM migration_fixture;',target),'0')
        finally:
            for name in (target,source):m.sql('DROP DATABASE IF EXISTS '+m.identifier(name)+' WITH (FORCE);')

class ImportFlow(Base):
    def fixture(self):
        import importlib.util
        spec=importlib.util.spec_from_file_location('migration_import',Path(m.__file__).with_name('migrate-import.py'))
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        # The CLI deliberately limits real destinations to application directories.
        self.home_temp=tempfile.TemporaryDirectory(prefix='migration-cli-test-',dir=Path.home())
        self.addCleanup(self.home_temp.cleanup)
        root=Path(self.home_temp.name)/'app';root.mkdir()
        source_root=Path('/srv/old-bearportal');state_root=self.root/'state';state_root.mkdir()
        stage=self.stage();meta=dict(protocol=1,id=str(uuid.uuid4()),source_root=str(source_root),hostname='app.example',origin='https://app.example',source_ip='8.8.8.8',commit='a'*40,branch='main',node_version='v22.21.1',pnpm='pnpm@10.15.0',pg_major=17,database='fixture',owner_role='fixture_owner',app_role='fixture_app',snapshot={})
        m.write_json(stage/'manifest.json',meta);archive=self.root/'source.tar.gz';digest=m.pack(stage,archive)
        state=dict(source='admin@old.example',source_root=str(source_root),root=str(root),user='bearportal',target_ip='8.8.4.4',phase='prepared',source_commit=meta['commit'],runtime='/opt/runtime')
        m.write_json(state_root/'import.json',state)
        calls=[];fail_forward=[False]
        def remote(_args,_root,*flags,output=None):
            calls.append(flags[0])
            if flags[0]=='--inspect':return json.dumps({**meta,'fenced':False}).encode()
            if flags[0]=='--wait-seconds':return json.dumps(dict(id=meta['id'],bundle='/private/source.tar.gz',sha256=digest)).encode()
            if flags[0]=='--forward-to':
                self.assertTrue((root/m.FENCE_NAME).exists(),'Target must still be fenced when forwarding starts')
                if fail_forward[0]:raise m.MigrationError('simulated forwarding failure')
                return b'{"forwarding":true}'
            if flags[0]=='--verify-target':
                self.assertFalse((root/m.FENCE_NAME).exists());return b'{"ok":true}'
            raise AssertionError(flags)
        def transfer(_host,_command,output=None,**_):output.write(archive.read_bytes());return b''
        def configure(_stage,_root,*_):
            self.assertTrue((root/m.FENCE_NAME).exists())
            m.atomic_write(root/'.data/trial/env','PORT=8088\n');return {'PORT':'8088'}
        argv=['migrate-import.py','--from',state['source'],'--source-root',str(source_root),'--app-dir',str(root),'--public-ip',state['target_ip'],'--resume']
        return module,root,state_root,meta,calls,fail_forward,remote,transfer,configure,argv
    def test_import_does_not_unfence_target_before_source_handoff(self):
        module,root,state_root,meta,calls,fail,remote,transfer,configure,argv=self.fixture()
        with patch.object(m,'STATE_ROOT',state_root),patch.object(m,'require_root'),patch.object(module,'remote',side_effect=remote),patch.object(m,'source_ssh',side_effect=transfer),patch.object(m,'create_target_database')as create,patch.object(module,'ownership',return_value=True),patch.object(m,'snapshot',return_value={}),patch.object(m,'restore_database')as restore,patch.object(m,'configure_target',side_effect=configure),patch.object(m,'run'),patch.object(module,'wait_local'),patch.object(sys,'argv',argv),patch('sys.stdout',new_callable=io.StringIO):
            module.main()
        self.assertEqual(m.read_json(state_root/'import.json')['phase'],'complete')
        self.assertEqual(create.call_count,1);self.assertEqual(restore.call_count,1)
        self.assertLess(calls.index('--forward-to'),calls.index('--verify-target'))
        self.assertFalse((root/m.FENCE_NAME).exists())
    def test_resume_after_forwarding_failure_never_restores_twice(self):
        module,root,state_root,meta,calls,fail,remote,transfer,configure,argv=self.fixture();fail[0]=True
        with patch.object(m,'STATE_ROOT',state_root),patch.object(m,'require_root'),patch.object(module,'remote',side_effect=remote),patch.object(m,'source_ssh',side_effect=transfer),patch.object(m,'create_target_database'),patch.object(module,'ownership',return_value=True),patch.object(m,'snapshot',return_value={}),patch.object(m,'restore_database')as restore,patch.object(m,'configure_target',side_effect=configure)as configured,patch.object(m,'run'),patch.object(module,'wait_local'),patch.object(sys,'argv',argv),patch('sys.stdout',new_callable=io.StringIO):
            with self.assertRaises(m.MigrationError):module.main()
            self.assertEqual(m.read_json(state_root/'import.json')['phase'],'configured');self.assertTrue((root/m.FENCE_NAME).exists())
            fail[0]=False;module.main()
            self.assertEqual(restore.call_count,1);self.assertEqual(configured.call_count,1)
        self.assertEqual(m.read_json(state_root/'import.json')['phase'],'complete')

class CaddyCache(Base):
    @unittest.skipUnless(shutil.which('caddy') and shutil.which('openssl'),'Caddy/OpenSSL not installed')
    def test_generated_caddy_configuration_uses_trusted_original_client_ip(self):
        path=self.root/'Caddyfile';path.write_text(m.target_caddy_config('app.example','8.8.8.8',8088))
        config=json.loads(m.run(['caddy','adapt','--config',path,'--adapter','caddyfile']))
        servers=config['apps']['http']['servers'];server=next(iter(servers.values()))
        self.assertEqual(server['trusted_proxies']['ranges'],['8.8.8.8/32'])
        self.assertTrue(server['trusted_proxies_strict'])


    @unittest.skipUnless(shutil.which('caddy') and shutil.which('openssl'),'Caddy/OpenSSL not installed')
    def test_copied_certificate_serves_https_without_dns_change(self):
        import socket, ssl, time
        host='migration.test'
        def port():
            with socket.socket() as listener:
                listener.bind(('127.0.0.1',0));return listener.getsockname()[1]
        def launch(storage):
            https_port=port();http_port=port()
            config=storage.parent/(storage.name+'.Caddyfile')
            config.write_text('{\n admin off\n skip_install_trust\n auto_https disable_redirects\n http_port '+str(http_port)+'\n https_port '+str(https_port)+'\n storage file_system '+str(storage)+'\n}\n'+host+' {\n bind 127.0.0.1\n tls internal\n respond "ready"\n}\n')
            child=subprocess.Popen(['caddy','run','--config',str(config),'--adapter','caddyfile'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            return child,https_port
        source=self.root/'source-cache';child,https_port=launch(source)
        try:
            for _ in range(100):
                cert=source/'certificates/local'/host/(host+'.crt')
                if cert.exists():break
                time.sleep(.05)
            self.assertTrue(cert.exists())
            source_root=source/'pki/authorities/local/root.crt'
            context=ssl.create_default_context(cafile=str(source_root))
            with socket.create_connection(('127.0.0.1',https_port),timeout=3) as raw:
                with context.wrap_socket(raw,server_hostname=host) as secure:original=secure.getpeercert(binary_form=True)
            stage=self.root/'stage';m.copy_tls(stage,host,source)
        finally:
            child.terminate();child.wait(timeout=10)
        destination=self.root/'destination-cache';shutil.copytree(stage/'tls',destination)
        child,https_port=launch(destination)
        try:
            # Trust ONLY the old CA. The target has no old CA key or DNS changes.
            for attempt in range(100):
                try:
                    with socket.create_connection(('127.0.0.1',https_port),timeout=1) as raw:
                        with context.wrap_socket(raw,server_hostname=host) as secure:
                            self.assertEqual(secure.getpeercert(binary_form=True),original)
                            return
                except OSError:
                    if attempt==99:raise
                    time.sleep(.05)
        finally:
            child.terminate();child.wait(timeout=10)


if __name__=='__main__':unittest.main(verbosity=2)

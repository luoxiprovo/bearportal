"""Shared, standard-library-only migration operations. CLI entrypoints require root.

All commands use argument arrays. Database passwords and application secrets never
appear in arguments, progress output, manifests, or exception messages.
"""
from __future__ import annotations
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import secrets
import shlex
import shutil
import socket
import ssl
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import uuid

PROTOCOL = 1
STATE_ROOT = Path('/var/lib/bearportal-migration')
FENCE_NAME = '.data/server-migration-source.lock'
SERVICE = 'bearportal-api.service'
CADDY_DATA = Path('/var/lib/caddy/.local/share/caddy')
SSH_DIR = Path('/var/lib/bearportal/ssh')

class MigrationError(Exception):
    pass

def require_root():
    if os.geteuid() != 0:
        raise MigrationError('Run this command with sudo. It needs local PostgreSQL and service administration.')

def run(args, *, data=None, cwd=None, env=None, output=None, label=None):
    args=[str(x) for x in args]
    if args[0]=='git' and cwd is not None and os.geteuid()==0 and Path(cwd).stat().st_uid!=0:
        args=['runuser','-u',pwd.getpwuid(Path(cwd).stat().st_uid).pw_name,'--']+args
    result = subprocess.run(args, input=data, cwd=cwd, env=env,
                            stdout=output if output is not None else subprocess.PIPE,
                            stderr=subprocess.PIPE)
    if result.returncode:
        # Do not echo stderr: it can contain SQL, URLs, or source environment values.
        raise MigrationError(f'{label or Path(str(args[0])).name} failed (exit {result.returncode}). No private command output was logged.')
    return result.stdout if output is None else b''

def say(message):
    print('[bearportal-migration] '+message, file=__import__('sys').stderr, flush=True)

def private_dir(path):
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    return path

def atomic_write(path, content, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.'+path.name, dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content.encode() if isinstance(content, str) else content)
            stream.flush(); os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name): os.unlink(name)

def write_json(path, value):
    atomic_write(path, json.dumps(value, indent=2)+'\n')

def read_json(path):
    return json.loads(Path(path).read_text())

def parse_env(text):
    result = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'): continue
        if '=' not in line: raise MigrationError('Unsupported environment syntax; use NAME=value lines.')
        key, value = line.split('=', 1)
        if not re.fullmatch(r'[A-Z][A-Z0-9_]*', key) or key in result:
            raise MigrationError('Invalid or duplicate environment variable name.')
        if value.startswith('"'):
            try: value = json.loads(value)
            except (ValueError, TypeError): raise MigrationError('Unsupported quoted environment value.')
        elif value.startswith("'"):
            if not value.endswith("'"): raise MigrationError('Unclosed environment quote.')
            value = value[1:-1]
        if not isinstance(value, str) or any(c in value for c in '\n\r\0'):
            raise MigrationError('Multiline environment values are not supported.')
        result[key] = value
    return result

def render_env(env):
    return ''.join(f'{key}={json.dumps(value, ensure_ascii=False)}\n' for key, value in sorted(env.items()))

def identifier(value):
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,62}', value):
        raise MigrationError('Unsupported database or role identifier.')
    return '"'+value+'"'

def literal(value):
    return "'"+value.replace("'", "''")+"'"

def db_spec(env):
    specs = []
    for name in ('DATABASE_URL', 'MIGRATION_DATABASE_URL'):
        try:
            url = urllib.parse.urlsplit(env[name])
            if url.scheme not in ('postgres', 'postgresql') or url.hostname not in ('127.0.0.1', 'localhost', '::1'):
                raise ValueError()
            database = urllib.parse.unquote(url.path.removeprefix('/'))
            role = urllib.parse.unquote(url.username or '')
            identifier(database); identifier(role)
            specs.append(dict(database=database, role=role, port=url.port or 5432))
        except (ValueError, KeyError):
            raise MigrationError('These scripts require a local PostgreSQL database and valid database URL settings.')
    app, owner = specs
    if (app['database'], app['port']) != (owner['database'], owner['port']) or app['role'] == owner['role']:
        raise MigrationError('Application and migration URLs must use distinct roles in the same local database.')
    return dict(database=app['database'], app_role=app['role'], owner_role=owner['role'], port=app['port'])

def pg_command(tool, database, port=5432):
    prefix=['runuser','-u','postgres','--'] if os.geteuid()==0 else ['sudo','-n','-u','postgres','--']
    return prefix+[tool, '--host=/var/run/postgresql', '--port='+str(port), '--dbname='+database]

def pg_env():
    return {**{k:v for k,v in os.environ.items() if not k.startswith('PG')}, 'PGAPPNAME':'bearportal_migration'}

def sql(text, database='postgres', port=5432):
    return run(pg_command('psql', database, port)+['-X','-qAt','-v','ON_ERROR_STOP=1'], data=text.encode(), env=pg_env(), label='Local PostgreSQL administration').decode().strip()

def rows(query, database, port=5432):
    return json.loads(sql("SELECT coalesce(json_agg(t),'[]'::json) FROM ("+query+") t;", database, port))

def snapshot(database, port=5432):
    tables = rows("SELECT c.relname,c.relrowsecurity,c.relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p') ORDER BY c.relname", database, port)
    return {t['relname']:dict(count=int(sql('SELECT count(*) FROM public.'+identifier(t['relname']), database, port)),
                             rls=t['relrowsecurity'], force_rls=t['relforcerowsecurity']) for t in tables}

def compare_snapshot(expected, actual):
    if expected != actual:
        raise MigrationError('Restored table counts or row-level-security settings do not match the source. The target remains fenced.')

def file_hash(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024), b''): digest.update(chunk)
    return digest.hexdigest()

def pack(stage, destination):
    stage, destination = Path(stage), Path(destination)
    manifest = read_json(stage/'manifest.json')
    manifest['files'] = {p.relative_to(stage).as_posix():dict(sha256=file_hash(p), size=p.stat().st_size)
                         for p in sorted(stage.rglob('*')) if p.is_file() and p.name != 'manifest.json'}
    write_json(stage/'manifest.json', manifest)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open('xb') as output:
        os.fchmod(output.fileno(), 0o600)
        with tarfile.open(fileobj=output, mode='w:gz') as archive:
            for path in sorted(stage.rglob('*')):
                if path.is_symlink(): raise MigrationError('Symlinks are not permitted in a migration bundle.')
                if path.is_file(): archive.add(path, arcname=path.relative_to(stage).as_posix(), recursive=False)
    return file_hash(destination)

def unpack(archive_path, stage):
    stage = private_dir(stage)
    seen = set()
    with tarfile.open(archive_path, 'r:gz') as archive:
        for entry in archive:
            name = PurePosixPath(entry.name)
            if (name.is_absolute() or '..' in name.parts or not entry.isfile() or entry.name in seen
                or not name.parts or name.parts[0] not in ('manifest.json','database.dump','code.bundle','config','secrets','ssh','tls')):
                raise MigrationError('Unsafe or unexpected migration archive member.')
            if len(seen) >= 200000 or entry.size < 0: raise MigrationError('Unsupported archive size.')
            seen.add(entry.name)
            target = stage.joinpath(*name.parts)
            private_dir(target.parent)
            source = archive.extractfile(entry)
            with target.open('xb') as output:
                os.fchmod(output.fileno(), 0o600)
                shutil.copyfileobj(source, output, 1024*1024)
    manifest = read_json(stage/'manifest.json')
    if manifest.get('protocol') != PROTOCOL: raise MigrationError('Unsupported migration protocol.')
    declared = manifest.get('files', {})
    if not isinstance(declared, dict) or set(declared) != seen-{'manifest.json'}:
        raise MigrationError('Migration bundle file inventory is incomplete.')
    for name, expected in declared.items():
        path = stage/name
        if path.stat().st_size != expected['size'] or file_hash(path) != expected['sha256']:
            raise MigrationError('Migration bundle checksum verification failed.')
    return manifest

def checked_ip(value):
    try: ip = ipaddress.ip_address(value)
    except ValueError: raise MigrationError('A literal public server IP address is required.')
    if not ip.is_global or not isinstance(ip,ipaddress.IPv4Address): raise MigrationError('A public IPv4 server address is required.')
    return str(ip)

def public_ip():
    try:
        request=urllib.request.Request('http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip', headers={'Metadata-Flavor':'Google'})
        return checked_ip(urllib.request.urlopen(request, timeout=2).read().decode().strip())
    except Exception:
        raise MigrationError('Cannot detect this server’s public IP. Supply --public-ip explicitly.')

def origin_host(value):
    url = urllib.parse.urlsplit(value)
    if url.scheme != 'https' or url.username or url.password or url.port not in (None,443) or url.path not in ('','/') or url.query or url.fragment or not url.hostname:
        raise MigrationError('A canonical HTTPS origin on port 443 is required.')
    host = url.hostname.encode('idna').decode()
    if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?',host) or '..' in host:
        raise MigrationError('Invalid public hostname.')
    return host

def https_health(host, ip, *, maintenance=False, port=443, context=None):
    connection = http.client.HTTPSConnection(host, port, timeout=10, context=context or ssl.create_default_context())
    # Preserve SNI, hostname verification and Host while bypassing stale DNS caches.
    connection.sock = (context or ssl.create_default_context()).wrap_socket(socket.create_connection((ip,port),timeout=10),server_hostname=host)
    try:
        connection.request('GET','/healthz',headers={'Host':host})
        response=connection.getresponse(); value=json.loads(response.read())
        if response.status != (503 if maintenance else 200) or value.get('migrationProtocol')!=PROTOCOL or bool(value.get('maintenance'))!=maintenance or bool(value.get('ok'))==maintenance:
            raise MigrationError('The destination API did not report the expected migration state.')
        return value
    finally: connection.close()

def service_value(name, service=SERVICE):
    return run(['systemctl','show',service,'--property='+name,'--value'],label='Service inspection').decode().strip()

def source_inspect(root, env_file=None, address=None):
    root=Path(root).resolve()
    if run(['git','status','--porcelain'],cwd=root).strip():
        raise MigrationError('Commit or remove tracked/untracked source changes before exporting. Private .data files remain excluded.')
    env_file=Path(env_file or root/'.data/trial/env').resolve()
    env=parse_env(env_file.read_text()); spec=db_spec(env)
    if env.get('BEARPORTAL_ENV')!='production' or env.get('BEARPORTAL_ALLOW_TEST_ISSUER')=='1':
        raise MigrationError('Production configuration with the test issuer disabled is required.')
    if not re.fullmatch(r'[a-fA-F0-9]{64}',env.get('BEARPORTAL_SECRET_KEY','')):
        raise MigrationError('The existing encryption key is missing or invalid.')
    host=origin_host(env.get('BEARPORTAL_BILLING_ORIGIN') or env.get('BEARPORTAL_AUTH_ORIGINS','').split(',')[0])
    branch=run(['git','symbolic-ref','--short','HEAD'],cwd=root).decode().strip()
    commit=run(['git','rev-parse','HEAD'],cwd=root).decode().strip()
    service_env=shlex.split(service_value('Environment'))
    service_path=next((value.split('=',1)[1] for value in service_env if value.startswith('PATH=')),os.defpath)
    node=shutil.which('node',path=service_path)
    if not node:
        source_user=service_value('User') or 'root'
        node=str(Path(pwd.getpwnam(source_user).pw_dir)/'.local/bin/node')
    version=run([node,'--version']).decode().strip()
    if not re.fullmatch(r'v22\.\d+\.\d+',version): raise MigrationError('This migration release supports Node.js 22 sources.')
    pg_major=int(sql("SELECT current_setting('server_version_num')::int/10000",spec['database'],spec['port']))
    if pg_major!=17: raise MigrationError('This migration release supports PostgreSQL 17 sources.')
    package=json.loads((root/'package.json').read_text())
    manager=package.get('packageManager','')
    if not re.fullmatch(r'pnpm@\d+\.\d+\.\d+',manager): raise MigrationError('A pinned pnpm packageManager is required.')
    machines=rows("SELECT DISTINCT host(s.public_ipv4) AS ip FROM servers s WHERE s.state IN ('available','reserved','assigned','quarantined') ORDER BY ip",spec['database'],spec['port'])
    config=json.loads(run(['caddy','adapt','--config','/etc/caddy/Caddyfile','--adapter','caddyfile'],label='Source HTTPS configuration preflight'))
    forwarding_config(config,host,'8.8.8.8')
    fence=root/FENCE_NAME
    if not fence.exists():
        try:
            value=json.load(urllib.request.urlopen('http://127.0.0.1:'+env.get('PORT','8088')+'/healthz',timeout=5))
        except Exception: raise MigrationError('The source API must be running for migration preflight.')
        if value.get('migrationProtocol')!=PROTOCOL: raise MigrationError('Deploy/restart the migration-aware source API before exporting.')
    remote=run(['git','remote','get-url','origin'],cwd=root).decode().strip()
    if remote.startswith('git@github.com:'): remote='https://github.com/'+remote.split(':',1)[1]
    if remote.startswith(('https://','http://')):
        parsed=urllib.parse.urlsplit(remote);remote=urllib.parse.urlunsplit((parsed.scheme,parsed.hostname or '',parsed.path,'',''))
    result=dict(git_remote=remote,database_size_bytes=int(sql('SELECT pg_database_size(current_database())',spec['database'],spec['port'])),protocol=PROTOCOL,source_root=str(root),source_env=str(env_file),source_ip=checked_ip(address) if address else public_ip(),
                hostname=host,origin='https://'+host,branch=branch,commit=commit,node_version=version,pnpm=manager,
                database=spec['database'],app_role=spec['app_role'],owner_role=spec['owner_role'],pg_major=pg_major,
                mail_servers=[m['ip'] for m in machines],fenced=fence.exists(),service_enabled=service_value('UnitFileState')=='enabled')
    if fence.exists():
        saved=read_json(fence);result['handoff']={key:saved.get(key) for key in ('id','phase','bundle','sha256','destination_ip')}
    return result,env,spec

def copy_private(source,destination):
    source,destination=Path(source),Path(destination)
    if not source.is_file(): raise MigrationError('A required private migration file is missing.')
    private_dir(destination.parent); atomic_write(destination,source.read_bytes())

def copy_ssh(stage, inventory):
    for name in ('id_ed25519','id_ed25519.pub','known_hosts'):
        path=SSH_DIR/name
        if path.is_file(): copy_private(path,Path(stage)/'ssh'/name)
    if inventory and (not (Path(stage)/'ssh/id_ed25519').is_file() or not (Path(stage)/'ssh/known_hosts').is_file()):
        raise MigrationError('Existing mail-server inventory requires the original SSH private key and known_hosts.')

def copy_tls(stage, host, data_dir=CADDY_DATA):
    found=0
    for folder in (Path(data_dir)/'certificates').glob('*/'+host):
        cert,key=folder/(host+'.crt'),folder/(host+'.key')
        if not cert.is_file() or not key.is_file(): continue
        run(['openssl','x509','-in',cert,'-noout','-checkhost',host,'-checkend','3600'],label='Source TLS certificate validation')
        cert_public=run(['openssl','x509','-in',cert,'-pubkey','-noout'])
        key_public=run(['openssl','pkey','-in',key,'-pubout'])
        if cert_public!=key_public: raise MigrationError('TLS certificate changed during capture. Retry before moving the API.')
        for path in folder.iterdir():
            if path.is_file(): copy_private(path,Path(stage)/'tls'/path.relative_to(data_dir))
        found+=1
    if not found: raise MigrationError('No reusable Caddy certificate was found for the application hostname.')

def wait_drained(root, spec, timeout):
    deadline=time.monotonic()+timeout; idle=0
    while time.monotonic()<deadline:
        counts=rows("SELECT (SELECT count(*) FROM jobs WHERE state='running')+(SELECT count(*) FROM onboarding_requests WHERE state='installing') AS jobs, (SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND usename="+literal(spec['app_role'])+" AND state<>'idle') AS transactions",spec['database'],spec['port'])[0]
        idle=idle+1 if counts['jobs']==0 and counts['transactions']==0 else 0
        if idle>=3: return
        if int(deadline-time.monotonic())%10==0: say('Waiting for '+str(counts['jobs'])+' active install/job(s) and '+str(counts['transactions'])+' transaction(s)…')
        time.sleep(1)
    raise MigrationError('A running installation or transaction did not finish before the deadline. The source was not stopped.')

def create_git_bundle(root,output,branch):
    with Path(output).open('wb') as stream:
        os.fchmod(stream.fileno(),0o600)
        run(['git','bundle','create','-','HEAD',branch],cwd=root,output=stream,label='Source code snapshot')


def export_bundle(root, output, *, env_file=None, address=None, timeout=1800):
    root=Path(root).resolve(); meta,env,spec=source_inspect(root,env_file,address)
    if meta['fenced']: raise MigrationError('The source is already fenced. Resume the existing handoff or explicitly roll back first.')
    fence=root/FENCE_NAME; private_dir(fence.parent)
    migration_id=str(uuid.uuid4())
    record=dict(role='source',id=migration_id,source_ip=meta['source_ip'],hostname=meta['hostname'],phase='draining',created_at=time.time(),service_enabled=meta['service_enabled'])
    # Exclusive creation prevents simultaneous exports.
    with fence.open('x') as stream: os.fchmod(stream.fileno(),0o600);json.dump(record,stream)
    stopped=False
    stage=Path(tempfile.mkdtemp(prefix='export-',dir=private_dir(STATE_ROOT)))
    try:
        say('Blocking new mutations and waiting for running installations to finish…')
        wait_drained(root,spec,timeout)
        run(['systemctl','stop',SERVICE]); stopped=True
        run(['systemctl','disable',SERVICE])
        record['phase']='exporting';write_json(fence,record)
        if service_value('ActiveState') not in ('inactive','failed'): raise MigrationError('The source API did not stop.')
        meta.update(id=migration_id,created_at=time.time(),snapshot=snapshot(spec['database'],spec['port']))
        say('Capturing PostgreSQL, encrypted credentials, SSH access, code and HTTPS certificate…')
        with (stage/'database.dump').open('wb') as stream:
            os.fchmod(stream.fileno(),0o600)
            run(pg_command('pg_dump',spec['database'],spec['port'])+['--format=custom'],output=stream,env=pg_env(),label='Consistent PostgreSQL export')
        run(['pg_restore','--list',stage/'database.dump'],label='Database archive validation')
        create_git_bundle(root,stage/'code.bundle',meta['branch'])
        copy_private(meta['source_env'],stage/'config/env')
        public=Path(env['BEARPORTAL_JWT_PUBLIC_KEY_FILE']);public=public if public.is_absolute() else root/public
        copy_private(public,stage/'config/identity-public.pem')
        directory=Path(env['BEARPORTAL_SECRETS_DIR']);directory=directory if directory.is_absolute() else root/directory
        for path in directory.glob('*.bin'):
            if not re.fullmatch(r'[0-9a-f-]{36}\.bin',path.name): raise MigrationError('Unexpected secret-store filename.')
            copy_private(path,stage/'secrets'/path.name)
        for item in rows("SELECT file_name FROM secret_refs WHERE state='active'",spec['database'],spec['port']):
            if not (stage/'secrets'/item['file_name']).is_file(): raise MigrationError('An active credential file is missing; export cancelled.')
        copy_ssh(stage,meta['mail_servers']);copy_tls(stage,meta['hostname'])
        write_json(stage/'manifest.json',meta)
        digest=pack(stage,output)
        record.update(phase='exported',bundle=str(Path(output).resolve()),sha256=digest)
        write_json(fence,record)
        caller=os.environ.get('SUDO_USER')
        if caller:
            user=pwd.getpwnam(caller);os.chown(output,user.pw_uid,user.pw_gid)
        say('Export complete. The old API is stopped and startup-fenced; its HTTPS proxy remains running.')
        return dict(id=migration_id,bundle=str(Path(output).resolve()),sha256=digest)
    except Exception:
        if not stopped:
            fence.unlink(missing_ok=True)
        else:
            record['phase']='export_failed';write_json(fence,record)
            say('The source remains fenced. Use the documented rollback command before restarting it.')
        raise
    finally: shutil.rmtree(stage)

def source_ssh(host, command, *, output=None, binary=False):
    if not re.fullmatch(r'(?:[A-Za-z0-9_.-]+@)?[A-Za-z0-9_.:-]+',host) or host.startswith('-'):
        raise MigrationError('Invalid source SSH destination.')
    args=['ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=10',host,shlex.join([str(x) for x in command])]
    user=os.environ.get('SUDO_USER')
    if user and user!='root': args=['runuser','-u',user,'--']+args
    process=subprocess.Popen(args,stdout=output if output is not None else subprocess.PIPE,stderr=subprocess.PIPE)
    def progress():
        for line in process.stderr:
            text=line.decode('utf8','replace').strip()
            if text.startswith('[bearportal-migration] '): print(text,file=__import__('sys').stderr,flush=True)
    thread=threading.Thread(target=progress,daemon=True);thread.start()
    result=process.stdout.read() if output is None else b''
    status=process.wait();thread.join()
    if status: raise MigrationError('Source SSH command failed (exit '+str(status)+'). Verify SSH host trust, key access and passwordless sudo; any migration diagnostic is shown above.')
    return result

class PortProbe:
    def __enter__(self):
        self.sockets=[];self.stopping=False;self.threads=[]
        try:
            for port in (80,443):
                server=socket.socket();server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);server.bind(('0.0.0.0',port));server.listen();server.settimeout(.2);self.sockets.append(server)
                def accept_loop(sock=server):
                    while not self.stopping:
                        try: connection,_=sock.accept();connection.close()
                        except (TimeoutError,OSError): pass
                thread=threading.Thread(target=accept_loop,daemon=True);thread.start();self.threads.append(thread)
            return self
        except Exception:
            self.__exit__(None,None,None);raise MigrationError('Target ports 80/443 are already used by another web service.')
    def __exit__(self,*_):
        self.stopping=True
        for server in self.sockets: server.close()
        for thread in self.threads: thread.join(timeout=1)

def probe_ports(ip):
    ip=checked_ip(ip)
    result={}
    for port in (80,443):
        try:
            with socket.create_connection((ip,port),timeout=5): result[str(port)]=True
        except OSError: result[str(port)]=False
    return result

def check_mail_access(stage, machines):
    for ip in machines:
        checked_ip(ip)
        run(['ssh','-i',Path(stage)/'ssh/id_ed25519','-o','IdentitiesOnly=yes','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','GlobalKnownHostsFile=/dev/null','-o','UserKnownHostsFile='+str(Path(stage)/'ssh/known_hosts'),'-o','ConnectTimeout=8','-o','ConnectionAttempts=1','bearadmin@'+ip,'sudo','-n','true'],label='Mail-server SSH access from the destination ('+ip+')')

def forwarding_config(config, host, ip):
    ip=checked_ip(ip); count=0
    def visit(value):
        nonlocal count
        if isinstance(value,dict):
            if any(host in match.get('host',[]) for match in value.get('match',[]) if isinstance(match,dict)):
                if any(match.get('host')!=[host] for match in value.get('match',[]) if isinstance(match,dict) and 'host' in match): raise MigrationError('Give the application its own Caddy hostname block before migrating; other sites will not be changed.')
                value['handle']=[dict(handler='reverse_proxy',upstreams=[dict(dial=('['+ip+']' if ':' in ip else ip)+':443')],transport=dict(protocol='http',tls=dict(server_name=host)),headers=dict(request=dict(set={'Host':[host],'X-Forwarded-For':['{http.request.client_ip}']})))]
                count+=1;return
            for child in value.values(): visit(child)
        elif isinstance(value,list):
            for child in value: visit(child)
    visit(config)
    if count!=1: raise MigrationError('Cannot uniquely identify the BearPortal host in the old Caddy configuration.')
    return config

def forward_source(root, migration_id, ip, host):
    root=Path(root);fence=root/FENCE_NAME;record=read_json(fence)
    if record.get('id')!=migration_id or record.get('role')!='source' or service_value('ActiveState') not in ('inactive','failed'):
        raise MigrationError('Source fence/service state does not match this handoff.')
    if record.get('hostname')!=host or record.get('source_ip')==checked_ip(ip): raise MigrationError('Forwarding must keep the exported hostname and point to a different server.')
    https_health(host,checked_ip(ip),maintenance=True)
    config_path=Path('/etc/caddy/Caddyfile')
    config=json.loads(run(['caddy','adapt','--config',config_path,'--adapter','caddyfile'],label='Source proxy configuration inspection'))
    config=forwarding_config(config,host,ip)
    backup=private_dir(STATE_ROOT/migration_id)
    if not (backup/'Caddyfile.before').exists(): copy_private(config_path,backup/'Caddyfile.before')
    target=Path('/etc/caddy/bearportal-migration-forward.json');atomic_write(target,json.dumps(config),0o644)
    run(['caddy','validate','--config',target],label='Source forwarding validation')
    dropin=Path('/etc/systemd/system/caddy.service.d/bearportal-migration.conf')
    atomic_write(dropin,'[Service]\nExecStart=\nExecStart=/usr/bin/caddy run --environ --config '+str(target)+'\nExecReload=\nExecReload=/usr/bin/caddy reload --config '+str(target)+' --force\n',0o644)
    run(['systemctl','daemon-reload']);run(['systemctl','reload','caddy'])
    record.update(phase='forwarding',destination_ip=ip);write_json(fence,record)
    return dict(id=migration_id,forwarding=True)

def rollback_source(root, confirmed):
    if not confirmed: raise MigrationError('Stop/fence the target first, then pass --confirm-target-stopped to roll back.')
    fence=Path(root)/FENCE_NAME;record=read_json(fence)
    if record.get('role')!='source': raise MigrationError('This is not a source migration fence.')
    if record.get('phase')=='forwarding': raise MigrationError('Handoff already began. Resume the destination import instead; returning to the old database could lose new writes.')
    dropin=Path('/etc/systemd/system/caddy.service.d/bearportal-migration.conf')
    if dropin.exists():
        dropin.unlink();run(['systemctl','daemon-reload']);run(['systemctl','restart','caddy'])
    fence.unlink()
    if record.get('service_enabled'): run(['systemctl','enable',SERVICE])
    run(['systemctl','start',SERVICE])
    return dict(resumed=True)

def validate_manifest(meta):
    try:
        uuid.UUID(meta['id'])
        for key in ('database','app_role','owner_role'): identifier(meta[key])
        origin_host(meta['origin'])
        if meta['hostname']!=origin_host(meta['origin']) or meta['pg_major']!=17:
            raise ValueError()
        checked_ip(meta['source_ip'])
        if not re.fullmatch(r'[0-9a-f]{40,64}',meta['commit']) or not re.fullmatch(r'v22\.\d+\.\d+',meta['node_version']) or not re.fullmatch(r'pnpm@\d+\.\d+\.\d+',meta['pnpm']):
            raise ValueError()
        if not re.fullmatch(r'[A-Za-z0-9_./-]+',meta['branch']) or meta['branch'].startswith('-'):
            raise ValueError()
    except (KeyError,ValueError,TypeError): raise MigrationError('Invalid migration manifest.')

def download(url,path):
    if not url.startswith('https://'): raise MigrationError('Downloads must use HTTPS.')
    with urllib.request.urlopen(url,timeout=120) as response, Path(path).open('wb') as output:
        os.fchmod(output.fileno(),0o600);shutil.copyfileobj(response,output,1024*1024)

def ensure_target_tools(stage,meta):
    release=parse_env(Path('/etc/os-release').read_text())
    if release.get('ID')!='debian' or release.get('VERSION_ID')!='13':
        raise MigrationError('Automatic setup currently supports fresh Debian 13 servers. No source shutdown has happened.')
    say('Installing destination prerequisites (Debian 13, PostgreSQL 17, Caddy)…')
    apt_env={**os.environ,'DEBIAN_FRONTEND':'noninteractive'}
    run(['apt-get','update','-qq'],env=apt_env,label='Package index update')
    run(['apt-get','install','-y','ca-certificates','curl','gnupg','git','openssl','openssh-client','xz-utils','postgresql-17','postgresql-client-17'],env=apt_env,label='Destination prerequisites')
    # Use Caddy's signed official apt repository for trusted-proxy support.
    key=Path(stage)/'caddy.asc';download('https://dl.cloudsmith.io/public/caddy/stable/gpg.key',key)
    run(['gpg','--dearmor','--yes','-o','/usr/share/keyrings/caddy-stable-archive-keyring.gpg',key],label='Caddy repository key installation')
    Path('/usr/share/keyrings/caddy-stable-archive-keyring.gpg').chmod(0o644)
    apt_list=Path(stage)/'caddy.list';download('https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt',apt_list)
    atomic_write('/etc/apt/sources.list.d/caddy-stable.list',apt_list.read_bytes(),0o644)
    run(['apt-get','update','-qq'],env=apt_env,label='Caddy package index update')
    run(['apt-get','install','-y','caddy'],env=apt_env,label='Caddy installation')
    run(['systemctl','enable','--now','postgresql']);run(['systemctl','stop','caddy'])
    import platform
    arch={'x86_64':'x64','aarch64':'arm64'}.get(platform.machine())
    if not arch: raise MigrationError('Unsupported CPU architecture.')
    version=meta['node_version']; prefix=Path('/opt/bearportal-runtime')/('node-'+version+'-'+arch)
    if not (prefix/'bin/node').is_file():
        archive_name='node-'+version+'-linux-'+arch+'.tar.xz'
        archive=Path(stage)/archive_name;sums=Path(stage)/'SHASUMS256.txt'
        download('https://nodejs.org/dist/'+version+'/'+archive_name,archive)
        download('https://nodejs.org/dist/'+version+'/SHASUMS256.txt',sums)
        expected=next((line.split()[0] for line in sums.read_text().splitlines() if line.split()[-1]==archive_name),None)
        if not expected or file_hash(archive)!=expected: raise MigrationError('Node.js download checksum did not match.')
        prefix.parent.mkdir(parents=True,exist_ok=True)
        unpacked=Path(stage)/'node'
        if unpacked.exists(): shutil.rmtree(unpacked)
        unpacked.mkdir()
        with tarfile.open(archive,'r:xz') as bundle: bundle.extractall(unpacked,filter='data')
        shutil.move(str(unpacked/('node-'+version+'-linux-'+arch)),prefix)
        for path in [prefix,*prefix.rglob('*')]:
            if not path.is_symlink(): path.chmod(0o755 if path.is_dir() or path.stat().st_mode&0o111 else 0o644)
    command_env={**os.environ,'PATH':str(prefix/'bin')+':/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'}
    run([prefix/'bin/npm','install','--global','--prefix',prefix,meta['pnpm']],env=command_env,label='Pinned pnpm installation')
    return prefix,command_env

def target_caddy_config(host,source_ip,port):
    host=origin_host('https://'+host);source_ip=checked_ip(source_ip)
    subnet=source_ip+('/128' if ':' in source_ip else '/32')
    return ('{\n\tstorage file_system /var/lib/caddy/.local/share/caddy\n\tservers {\n\t\ttrusted_proxies static '+subnet+'\n\t\ttrusted_proxies_strict\n\t}\n}\n'+host+' {\n\treverse_proxy 127.0.0.1:'+str(int(port))+' {\n\t\theader_up X-Forwarded-For {client_ip}\n\t}\n}\n')

def service_unit(root,user,node_bin):
    for value in (str(root),user,str(node_bin)):
        if not re.fullmatch(r'[A-Za-z0-9_./-]+',value): raise MigrationError('Unsupported service path or user name.')
    return f'''[Unit]
Description=BearPortal API
After=network-online.target postgresql.service
Wants=network-online.target
Requires=postgresql.service

[Service]
Type=simple
User={user}
Group={user}
WorkingDirectory={root}
Environment=PATH={node_bin}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
EnvironmentFile={root}/.data/trial/env
ExecStart={node_bin}/node --import tsx apps/api/src/main.ts
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
UMask=0077

[Install]
WantedBy=multi-user.target
'''

def target_env(source,root,meta,passwords):
    env=dict(source);root=Path(root)
    for key in list(env):
        if key.startswith('BEARPORTAL_BACKUP_') or key in ('PATH','HOME','USER','LOGNAME','SHELL','NODE_OPTIONS','NODE_PATH','LD_PRELOAD','LD_LIBRARY_PATH','PGHOST','PGPORT','PGUSER','PGDATABASE','PGPASSWORD','PGOPTIONS'): del env[key]
    env.update(DATABASE_URL='postgres://'+meta['app_role']+':'+passwords['app']+'@127.0.0.1:5432/'+meta['database'],
               MIGRATION_DATABASE_URL='postgres://'+meta['owner_role']+':'+passwords['owner']+'@127.0.0.1:5432/'+meta['database'],
               BEARPORTAL_ENV='production',BEARPORTAL_ALLOW_TEST_ISSUER='0',BEARPORTAL_TEST_SKIP_SSH_HOST_KEY_CHECK='0',
               BEARPORTAL_JWT_PRIVATE_KEY_FILE='',BEARPORTAL_SECRETS_DIR=str(root/'.data/trial/secrets'),
               BEARPORTAL_JWT_PUBLIC_KEY_FILE=str(root/'.data/trial/identity-public.pem'),BEARPORTAL_BIND_HOST='127.0.0.1')
    if env.get('BEARPORTAL_SECRET_KEY')!=source.get('BEARPORTAL_SECRET_KEY'): raise MigrationError('Encryption key changed unexpectedly.')
    return env

def assert_empty_target_database(meta):
    name,owner,app=(meta[k] for k in ('database','owner_role','app_role'))
    if int(sql("SELECT current_setting('server_version_num')::int/10000",'postgres'))!=17: raise MigrationError('Destination PostgreSQL 17 must listen on local port 5432.')
    if rows('SELECT datname FROM pg_database WHERE datname='+literal(name),'postgres'):
        raise MigrationError('The destination database already exists. Refusing to overwrite it.')
    existing=rows('SELECT rolname FROM pg_roles WHERE rolname IN ('+literal(owner)+','+literal(app)+')','postgres')
    if existing: raise MigrationError('Destination database roles already exist. Use a fresh target or resolve their ownership explicitly.')

def create_target_database(meta,passwords,migration_id,*,resume=False):
    name,owner,app=(meta[k] for k in ('database','owner_role','app_role'))
    receipt='bearportal-migration:'+migration_id
    if not resume: assert_empty_target_database(meta)
    existing=rows("SELECT r.rolname,shobj_description(r.oid,'pg_authid') AS receipt FROM pg_roles r WHERE r.rolname IN ("+literal(owner)+','+literal(app)+')','postgres')
    if any(item['receipt']!=receipt for item in existing): raise MigrationError('Existing database roles belong to another deployment.')
    names={item['rolname'] for item in existing}
    statements=['BEGIN;']
    for role,secret in ((owner,passwords['owner']),(app,passwords['app'])):
        if role not in names:
            statements+=['CREATE ROLE '+identifier(role)+' LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD '+literal(secret)+';', 'COMMENT ON ROLE '+identifier(role)+' IS '+literal(receipt)+';']
    statements+=['COMMIT;'];sql('\n'.join(statements),'postgres')
    databases=rows("SELECT d.datname,pg_get_userbyid(d.datdba) AS owner,shobj_description(d.oid,'pg_database') AS receipt FROM pg_database d WHERE d.datname="+literal(name),'postgres')
    if not databases:
        sql('CREATE DATABASE '+identifier(name)+' OWNER '+identifier(owner)+';','postgres')
    elif databases[0]['owner']!=owner or databases[0]['receipt'] not in (None,receipt):
        raise MigrationError('Existing destination database is not owned by this import.')
    elif databases[0]['receipt'] is None and snapshot(name):
        raise MigrationError('Unmarked destination database contains tables; refusing to adopt it.')
    sql('COMMENT ON DATABASE '+identifier(name)+' IS '+literal(receipt)+';','postgres')


def restore_database(meta,archive):
    with Path(archive).open('rb') as stream:
        result=subprocess.run(pg_command('pg_restore',meta['database'])+['--exit-on-error','--single-transaction','--no-owner','--role='+meta['owner_role']],stdin=stream,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=pg_env())
    if result.returncode: raise MigrationError('Database restore failed and its transaction was rolled back. Private SQL output was suppressed.')
    compare_snapshot(meta['snapshot'],snapshot(meta['database']))
    roles=rows('SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname='+literal(meta['app_role']),meta['database'])
    if len(roles)!=1 or roles[0]['rolsuper'] or roles[0]['rolbypassrls']: raise MigrationError('Application role unexpectedly bypasses row-level security.')

def chown_tree(path,user):
    account=pwd.getpwnam(user);path=Path(path)
    for item in [path,*path.rglob('*')]:
        if item.is_symlink(): os.lchown(item,account.pw_uid,account.pw_gid)
        else: os.chown(item,account.pw_uid,account.pw_gid)

def configure_target(stage,root,meta,passwords,user,runtime,command_env):
    root=Path(root);source=parse_env((Path(stage)/'config/env').read_text());env=target_env(source,root,meta,passwords)
    directory=private_dir(root/'.data/trial');private_dir(directory/'secrets')
    atomic_write(directory/'env',render_env(env));copy_private(Path(stage)/'config/identity-public.pem',directory/'identity-public.pem')
    for path in (Path(stage)/'secrets').glob('*.bin'): copy_private(path,directory/'secrets'/path.name)
    private_dir(SSH_DIR);private_dir('/var/lib/bearportal/work')
    for path in (Path(stage)/'ssh').glob('*'): copy_private(path,SSH_DIR/path.name)
    chown_tree(root/'.data',user);chown_tree(SSH_DIR,user);chown_tree('/var/lib/bearportal/work',user)
    if not (SSH_DIR/'id_ed25519').exists():
        run(['ssh-keygen','-t','ed25519','-N','','-f',SSH_DIR/'id_ed25519'],label='Initial SSH key creation');chown_tree(SSH_DIR,user)
    for directory in (CADDY_DATA.parent.parent,CADDY_DATA.parent,CADDY_DATA):
        private_dir(directory);chown_tree(directory,'caddy')
    for path in (Path(stage)/'tls').rglob('*'):
        if path.is_file(): copy_private(path,CADDY_DATA/path.relative_to(Path(stage)/'tls'))
    chown_tree(CADDY_DATA,'caddy')
    atomic_write('/etc/caddy/Caddyfile',target_caddy_config(meta['hostname'],meta['source_ip'],env.get('PORT','8088')),0o644)
    run(['caddy','validate','--config','/etc/caddy/Caddyfile','--adapter','caddyfile'],label='Destination HTTPS configuration validation')
    atomic_write('/etc/systemd/system/'+SERVICE,service_unit(root,user,runtime/'bin'),0o644)
    run(['systemctl','daemon-reload'])
    run(['runuser','-u',user,'--',runtime/'bin/node','--env-file='+str(directory/'env'),'--import','tsx','packages/db/src/migrate.ts'],cwd=root,env=command_env,label='Pending database migrations')
    run(['runuser','-u',user,'--',runtime/'bin/node','--env-file='+str(directory/'env'),'--import','tsx','scripts/migration-verify.ts'],cwd=root,env=command_env,label='Restored encrypted-credential verification')
    return env

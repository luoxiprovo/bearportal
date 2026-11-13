#!/usr/bin/env python3
"""Prepare a fresh Debian 13 server and pull a fenced BearPortal migration over SSH."""
import argparse
import json
import os
from pathlib import Path
import pwd
import shutil
import sys
import time
import server_migration as m


def remote(args,root,*flags,output=None):
    return m.source_ssh(args.source,['sudo','-n','python3',str(root/'scripts/migrate-export.py'),'--root',str(root),*flags],output=output)


def ownership(database,migration_id):
    result=m.rows("SELECT shobj_description(oid,'pg_database') AS description FROM pg_database WHERE datname="+m.literal(database),'postgres')
    return bool(result and result[0]['description']=='bearportal-migration:'+migration_id)


def wait_local(port,maintenance):
    import urllib.request,urllib.error
    for _ in range(60):
        try:
            try: response=urllib.request.urlopen('http://127.0.0.1:'+str(port)+'/healthz',timeout=2)
            except urllib.error.HTTPError as error: response=error
            value=json.load(response)
            if value.get('migrationProtocol')==m.PROTOCOL and value.get('maintenance')==maintenance and value.get('ok')!=maintenance:return
        except (OSError,ValueError): pass
        time.sleep(.5)
    raise m.MigrationError('The destination service did not become ready. The source stays fenced; do not resume it while this target is running.')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--from',dest='source',help='SSH destination, for example admin@OLD_IP. SSH host verification and passwordless sudo must already work.')
    parser.add_argument('--source-root',type=Path,help='Defaults to the old service WorkingDirectory.')
    parser.add_argument('--app-dir',type=Path,default=Path('/opt/bearportal'))
    parser.add_argument('--user',default='bearportal',help='Dedicated destination service user (created if missing).')
    parser.add_argument('--public-ip',help='Detected automatically on Google Compute Engine.')
    parser.add_argument('--archive',type=Path,help='Use an existing export from the same fenced source instead of creating another.')
    parser.add_argument('--status',action='store_true',help='Show this destination checkpoint without contacting the old server.')
    parser.add_argument('--check',action='store_true',help='Check source, target ports and mail SSH without stopping the source or installing packages.')
    parser.add_argument('--resume',action='store_true',help='Continue a previously interrupted target import without restoring over live data.')
    parser.add_argument('--wait-seconds',type=int,default=1800)
    args=parser.parse_args();m.require_root();os.umask(0o077)
    if args.status:
        path=m.STATE_ROOT/'import.json'
        state=m.read_json(path) if path.exists() else {}
        print(json.dumps({key:state.get(key) for key in ('id','phase','source','target_ip','root')}));return
    if not args.source:parser.error('--from is required unless using --status')
    if not __import__('re').fullmatch(r'[a-z_][a-z0-9_-]*',args.user) or args.user in ('root','postgres','caddy'):
        raise m.MigrationError('Choose a dedicated, non-root BearPortal service user.')
    root=args.app_dir.resolve()
    if not __import__('re').fullmatch(r'/(?:opt|srv|home)/[A-Za-z0-9_./-]+',str(root)) or root.is_symlink():
        raise m.MigrationError('Use a normal application directory under /opt, /srv or /home.')
    source_root=args.source_root
    if source_root is None:
        source_root=Path(m.source_ssh(args.source,['systemctl','show',m.SERVICE,'--property=WorkingDirectory','--value']).decode().strip())
    if not source_root.is_absolute(): raise m.MigrationError('Cannot discover the source application directory.')
    source=json.loads(remote(args,source_root,'--inspect'))
    address=m.checked_ip(args.public_ip) if args.public_ip else m.public_ip()
    if address==source['source_ip']: raise m.MigrationError('Source and destination have the same public IP; refusing to migrate this server into itself.')
    state_path=m.STATE_ROOT/'import.json'
    state=m.read_json(state_path) if state_path.exists() else None
    if state:
        if state['source']!=args.source or state['source_root']!=str(source_root) or state['root']!=str(root) or state['target_ip']!=address or state['user']!=args.user:
            raise m.MigrationError('This destination already belongs to a different migration.')
        if state['phase']=='complete':
            m.https_health(source['hostname'],address)
            print(json.dumps({'complete':True,'url':source['origin'],'next':'Point DNS to '+address}));return
        if not args.resume and not args.check: raise m.MigrationError('An import checkpoint already exists. Use --resume to continue it.')
    elif root.exists() and any(root.iterdir()):
        raise m.MigrationError('Destination application directory is not empty. Use a fresh directory; no existing deployment will be overwritten.')
    elif m.service_value('LoadState')!='not-found':
        raise m.MigrationError('An existing BearPortal service was found on the destination. Use a fresh server.')
    if source['fenced'] and not (args.archive or args.resume and source.get('handoff',{}).get('phase') in ('exported','forwarding') or state and state.get('archive')):
        raise m.MigrationError('The source is already fenced. Supply its export with --archive or resume the original import checkpoint.')
    if not state and m.SSH_DIR.exists() and any(m.SSH_DIR.iterdir()): raise m.MigrationError('The destination already has mail-control SSH material; use a fresh server.')
    if not state and (m.CADDY_DATA/'certificates').exists() and any((m.CADDY_DATA/'certificates').iterdir()): raise m.MigrationError('The destination already hosts HTTPS certificates; use a fresh server.')
    workspace=m.private_dir(m.STATE_ROOT/'target')
    if not state or state['phase']=='preparing' or args.check:
        # Preflight carries code, SSH material and the HTTPS certificate; no database.
        preflight=workspace/'preflight.tar.gz'
        with preflight.open('wb') as stream:
            os.fchmod(stream.fileno(),0o600);remote(args,source_root,'--preflight',output=stream)
        unpacked=workspace/'preflight'
        if unpacked.exists():shutil.rmtree(unpacked)
        meta=m.unpack(preflight,unpacked);m.validate_manifest(meta)
        if meta['commit']!=source['commit']: raise m.MigrationError('Source code changed during preflight. Retry before moving the API.')
        if shutil.disk_usage(root.parent if root.parent.exists() else '/').free < source.get('database_size_bytes',0)*3+1024**3:
            raise m.MigrationError('The destination needs more free space for the archive, restored database and dependencies.')
        m.say('Checking SSH access to existing mail servers from the new server…')
        m.check_mail_access(unpacked,meta['mail_servers'])
        if not args.check:
            if state is None:
                state=dict(source=args.source,source_root=str(source_root),root=str(root),user=args.user,target_ip=address,phase='preparing',source_commit=source['commit'])
                m.write_json(state_path,state)
            runtime,command_env=m.ensure_target_tools(workspace,meta)
            state['runtime']=str(runtime);m.write_json(state_path,state)
            m.assert_empty_target_database(meta)
        # Both ports are tested from the OLD server, not merely from loopback.
        with m.PortProbe():
            ports=json.loads(remote(args,source_root,'--probe-target',address))
        if not all(ports.get(str(port)) for port in (80,443)):
            raise m.MigrationError('The old server cannot reach target TCP 80/443. Open its cloud firewall before continuing; the source API has not been stopped by this preflight.')
        if args.check:
            shutil.rmtree(unpacked);preflight.unlink()
            print(json.dumps({'preflight':True,'source_stopped':False,'target_ip':address,'mail_servers_checked':len(meta['mail_servers'])}));return
        if not root.exists() or not any(root.iterdir()):
            root.parent.mkdir(parents=True,exist_ok=True)
            m.run(['git','clone','--branch',meta['branch'],str(unpacked/'code.bundle'),root],label='Pinned application restore')
            if meta.get('git_remote'): m.run(['git','remote','set-url','origin',meta['git_remote']],cwd=root)
        if m.run(['git','rev-parse','HEAD'],cwd=root).decode().strip()!=meta['commit']:
            raise m.MigrationError('Destination code does not match the source snapshot.')
        try: pwd.getpwnam(args.user)
        except KeyError: m.run(['useradd','--system','--user-group','--home-dir','/var/lib/bearportal','--no-create-home','--shell','/usr/sbin/nologin',args.user],label='Service user creation')
        m.private_dir('/var/lib/bearportal');m.chown_tree('/var/lib/bearportal',args.user);m.chown_tree(root,args.user)
        command_env={**os.environ,'PATH':str(runtime/'bin')+':/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/var/lib/bearportal'}
        m.run(['runuser','-u',args.user,'--',runtime/'bin/pnpm','install','--frozen-lockfile'],cwd=root,env=command_env,label='Application dependency installation')
        state['phase']='prepared';m.write_json(state_path,state)
    runtime=Path(state['runtime'])
    command_env={**os.environ,'PATH':str(runtime/'bin')+':/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'}
    if state['phase']=='prepared':
        if args.archive:
            archive=args.archive.resolve()
            handoff=source.get('handoff') or {}
            if handoff.get('sha256')!=m.file_hash(archive): raise m.MigrationError('This export does not match the source fence receipt.')
            receipt={'id':handoff['id'],'bundle':str(archive),'sha256':handoff['sha256']}
        else:
            if source['fenced'] and args.resume:
                receipt=source['handoff']
            else:
                m.say('Preflight passed. Creating the consistent source export…')
                receipt=json.loads(remote(args,source_root,'--wait-seconds',str(args.wait_seconds)))
            archive=workspace/'export.tar.gz'
            with archive.open('wb') as stream:
                os.fchmod(stream.fileno(),0o600)
                m.source_ssh(args.source,['sudo','-n','cat','--',receipt['bundle']],output=stream)
        if m.file_hash(archive)!=receipt['sha256']: raise m.MigrationError('SSH-transferred bundle checksum did not match the source.')
        state.update(archive=str(archive),sha256=receipt['sha256'],id=receipt['id'],phase='received');m.write_json(state_path,state)
    stage=workspace/'restore'
    if not stage.exists():
        extraction=workspace/'restore-incomplete'
        if extraction.exists():shutil.rmtree(extraction)
        try:
            meta=m.unpack(state['archive'],extraction)
            extraction.rename(stage)
        except Exception:
            shutil.rmtree(extraction,ignore_errors=True)
            raise
    else:
        # Recheck the immutable archive on every resume, then use its already private extraction.
        if m.file_hash(state['archive'])!=state['sha256']: raise m.MigrationError('Saved export changed since the checkpoint.')
        meta=m.read_json(stage/'manifest.json')
        for name,value in meta['files'].items():
            if m.file_hash(stage/name)!=value['sha256']: raise m.MigrationError('Staged migration data changed.')
    m.validate_manifest(meta)
    if meta['id']!=state['id'] or meta['commit']!=state['source_commit'] or meta['source_root']!=str(source_root):
        raise m.MigrationError('The final export differs from the prepared source. Keep the source fenced and review the checkpoint.')
    fence=root/m.FENCE_NAME
    if state['phase']=='received':
        m.write_json(fence,dict(role='target',id=state['id'],created_at=time.time()))
        passwords={'app':__import__('secrets').token_hex(24),'owner':__import__('secrets').token_hex(24)}
        m.write_json(workspace/'database-passwords.json',passwords)
        state['phase']='creating';m.write_json(state_path,state)
    if state['phase']=='creating':
        passwords=m.read_json(workspace/'database-passwords.json')
        m.create_target_database(meta,passwords,state['id'],resume=True)
        state['phase']='restoring';m.write_json(state_path,state)
    if state['phase']=='restoring':
        if not ownership(meta['database'],state['id']): raise m.MigrationError('Destination database ownership receipt does not match.')
        current=m.snapshot(meta['database'])
        if current:
            m.compare_snapshot(meta['snapshot'],current)
        else:m.restore_database(meta,stage/'database.dump')
        state['phase']='restored';m.write_json(state_path,state)
    if state['phase']=='restored':
        if not fence.exists() or m.read_json(fence).get('id')!=state['id']: raise m.MigrationError('The target fence is missing; refusing to reconfigure a potentially live target.')
        passwords=m.read_json(workspace/'database-passwords.json')
        m.configure_target(stage,root,meta,passwords,args.user,runtime,command_env)
        state['phase']='configured';m.write_json(state_path,state)
    if state['phase']=='configured':
        m.run(['systemctl','enable','--now','caddy']);m.run(['systemctl','reload','caddy'])
        m.run(['systemctl','enable','--now',m.SERVICE]);wait_local(int(m.parse_env((root/'.data/trial/env').read_text()).get('PORT','8088')),True)
        # A real public HTTPS check, with normal certificate validation, happens on the source.
        result=json.loads(remote(args,source_root,'--forward-to',address,'--hostname',meta['hostname'],'--migration-id',state['id']))
        if not result.get('forwarding'):raise m.MigrationError('Source forwarding was not confirmed. The target remains in maintenance.')
        state['phase']='forwarding';m.write_json(state_path,state)
    if state['phase']=='forwarding':
        if not fence.exists() or m.read_json(fence).get('id')!=state['id']:raise m.MigrationError('The target fence does not match this import.')
        state['phase']='activating';m.write_json(state_path,state)
    if state['phase']=='activating':
        if fence.exists():
            if m.read_json(fence).get('id')!=state['id']:raise m.MigrationError('Target activation fence does not match.')
            fence.unlink()
        state['phase']='activated';m.write_json(state_path,state)
    if state['phase']=='activated':
        json.loads(remote(args,source_root,'--verify-target',address,'--hostname',meta['hostname']))
        state['phase']='complete';m.write_json(state_path,state)
        # Remove expanded secret copies; retain the 0600 export for deliberate rollback/audit.
        shutil.rmtree(stage);shutil.rmtree(workspace/'preflight',ignore_errors=True)
        (workspace/'database-passwords.json').unlink(missing_ok=True)
    print(json.dumps({'complete':True,'url':meta['origin'],'target_ip':address,'next':'Change the app DNS A record to '+address,'old_server':'API fenced; HTTPS forwards to the new server until DNS caches expire','checkpoint':str(state_path)}),flush=True)

if __name__=='__main__':
    try:main()
    except (m.MigrationError,OSError,ValueError,KeyError) as error:
        print(str(error) if isinstance(error,m.MigrationError) else 'Migration stopped while reading configuration or local state. Private data was not logged.',file=sys.stderr)
        print('Do not restart the old API while the target may be active. Correct the issue and rerun this command with --resume.',file=sys.stderr)
        sys.exit(1)

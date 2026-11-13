#!/usr/bin/env python3
"""Export/fence an old production server, or participate in an SSH handoff."""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import uuid
import server_migration as m

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--env-file',type=Path)
    parser.add_argument('--public-ip')
    parser.add_argument('--output',type=Path)
    parser.add_argument('--wait-seconds',type=int,default=1800)
    mode=parser.add_mutually_exclusive_group()
    mode.add_argument('--inspect',action='store_true')
    mode.add_argument('--preflight',action='store_true',help=argparse.SUPPRESS)
    mode.add_argument('--probe-target',help=argparse.SUPPRESS)
    mode.add_argument('--forward-to',help='Forward the old HTTPS hostname to a restored, fenced target IP.')
    mode.add_argument('--verify-target',help=argparse.SUPPRESS)
    mode.add_argument('--resume-source',action='store_true',help='Rollback only after the destination worker is stopped/fenced.')
    parser.add_argument('--migration-id')
    parser.add_argument('--hostname')
    parser.add_argument('--confirm-target-stopped',action='store_true')
    args=parser.parse_args();m.require_root();os.umask(0o077)
    if args.resume_source: result=m.rollback_source(args.root,args.confirm_target_stopped)
    elif args.probe_target: result=m.probe_ports(args.probe_target)
    elif args.verify_target: result=m.https_health(args.hostname,m.checked_ip(args.verify_target))
    elif args.forward_to: result=m.forward_source(args.root,args.migration_id,args.forward_to,args.hostname)
    elif args.inspect: result=m.source_inspect(args.root,args.env_file,args.public_ip)[0]
    elif args.preflight:
        meta,_,_=m.source_inspect(args.root,args.env_file,args.public_ip)
        with tempfile.TemporaryDirectory(prefix='preflight-',dir=m.private_dir(m.STATE_ROOT)) as directory:
            stage=Path(directory);meta['id']=str(uuid.uuid4());m.write_json(stage/'manifest.json',meta)
            m.copy_ssh(stage,meta['mail_servers'])
            m.copy_tls(stage,meta['hostname'])
            m.create_git_bundle(args.root,stage/'code.bundle',meta['branch'])
            archive=stage.parent/(stage.name+'.tar.gz')
            try:
                m.pack(stage,archive)
                with archive.open('rb') as stream: __import__('shutil').copyfileobj(stream,sys.stdout.buffer)
            finally: archive.unlink(missing_ok=True)
        return
    else:
        user=__import__('pwd').getpwnam(os.environ.get('SUDO_USER') or 'root')
        output=args.output or Path(user.pw_dir)/('bearportal-migration-'+str(uuid.uuid4())+'.tar.gz')
        result=m.export_bundle(args.root,output,env_file=args.env_file,address=args.public_ip,timeout=args.wait_seconds)
    print(json.dumps(result),flush=True)

if __name__=='__main__':
    try: main()
    except (m.MigrationError,OSError,ValueError,KeyError) as error:
        # Parsing/OS errors may include sensitive source text; show only known safe diagnostics.
        m.say('ERROR: '+(str(error) if isinstance(error,m.MigrationError) else 'Migration failed while reading configuration or local files. Private data was not logged.'))
        sys.exit(1)

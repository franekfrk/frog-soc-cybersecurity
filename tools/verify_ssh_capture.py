#!/usr/bin/env python3
"""Test live SSH credential capture, then remove only this run's credentials."""
import argparse
import base64
import contextlib
import html
import importlib.util
import json
import logging
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.request


def cleanup_spool(path, username, password):
    """Write as the spool owner, never leave root-owned SQLite journals."""
    path=Path(path)
    owner=path.stat()
    options={}
    if os.geteuid()==0:
        options={'user':owner.st_uid,'group':owner.st_gid,'extra_groups':[]}
    elif os.geteuid()!=owner.st_uid:
        raise PermissionError('Spool owner or root required')
    code='''import contextlib,json,sqlite3,sys
p=json.load(sys.stdin)
with contextlib.closing(sqlite3.connect('file:'+p['path']+'?mode=rw',uri=True,timeout=5)) as c, c:
 c.execute('PRAGMA secure_delete=ON')
 ids=[row[0] for row in c.execute('SELECT id FROM attempts WHERE username=? AND password=?',(p['user'],p['password']))]
 c.execute('DELETE FROM attempts WHERE username=? AND password=?',(p['user'],p['password']))
 assert c.execute('SELECT COUNT(*) FROM attempts WHERE username=? AND password=?',(p['user'],p['password'])).fetchone()[0]==0
print(json.dumps(ids))
'''
    result=subprocess.run([sys.executable,'-c',code],input=json.dumps({'path':str(path),'user':username,'password':password}),text=True,capture_output=True,check=True,timeout=15,umask=0o077,**options)
    return json.loads(result.stdout)


def cleanup_credentials(app, username, password, source_ids):
    with app.credentials_connect() as c:
        # Keep non-secret acknowledgements briefly, blocking an import already
        # in flight from restoring the row after this cleanup.
        c.executemany('INSERT OR IGNORE INTO imported_sources VALUES (?,?)',[(ident,time.time()) for ident in source_ids])
        c.execute("DELETE FROM submissions WHERE profile='ssh' AND username=? AND password=?",(username,password))
        remaining=c.execute("SELECT COUNT(*) FROM submissions WHERE username=? AND password=?",(username,password)).fetchone()[0]
        if remaining: raise RuntimeError('Test credentials remain in dashboard database')


def panel(app):
    auth=base64.b64encode(('frog:'+app.read_password()).encode()).decode()
    request=urllib.request.Request('http://127.0.0.1:'+str(app.PORT)+'/credentials',headers={'Authorization':'Basic '+auth})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request,timeout=5) as r:
        return r.read(2*1024*1024).decode()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app',default='/opt/frog-soc/app.py')
    args=parser.parse_args()
    if os.geteuid()!=0: parser.error('Run with sudo: private capture database and spool access required')
    import paramiko
    logging.disable(logging.CRITICAL)
    spec=importlib.util.spec_from_file_location('frog_verify',args.app)
    app=importlib.util.module_from_spec(spec);spec.loader.exec_module(app)
    if not app.CONFIG['ssh_capture']['enabled'] or not app.CONFIG['capture_credentials']:
        parser.error('SSH Capture and capture_credentials must be enabled')
    spool=Path(app.CONFIG['ssh_capture']['spool'])
    if not spool.is_file(): parser.error('SSH spool is missing; check frog-ssh service')
    if spool.stat().st_uid==0: parser.error('SSH spool must belong to the unprivileged SSH service user')
    username='__frog_full_test__'+secrets.token_hex(12)
    password=secrets.token_urlsafe(24)
    attempted=False;passed=False;cleaned=True;transport=None
    try:
        transport=paramiko.Transport(socket.create_connection(('127.0.0.1',app.ENDLESSH_PORT),timeout=5))
        transport.start_client(timeout=8)
        expected=paramiko.RSAKey.from_private_key_file(str(spool.parent/'host_rsa'))
        if transport.get_remote_server_key().asbytes()!=expected.asbytes():
            raise RuntimeError('SSH host key does not match the capture service')
        print('OK: SSH handshake and host key on port',app.ENDLESSH_PORT,flush=True)
        attempted=True
        try: transport.auth_password(username,password,fallback=False)
        except paramiko.AuthenticationException: pass
        else: raise RuntimeError('SSH authentication unexpectedly succeeded')
        if transport.is_authenticated(): raise RuntimeError('SSH authentication unexpectedly succeeded')
        transport.close();transport=None
        print('OK: password rejected; no authenticated session',flush=True)
        with contextlib.closing(sqlite3.connect('file:'+str(spool)+'?mode=ro',uri=True,timeout=5)) as c:
            rows=c.execute('SELECT id,ip,username,password FROM attempts WHERE username=? AND password=?',(username,password)).fetchall()
        if len(rows)!=1 or rows[0][1]!='127.0.0.1': raise RuntimeError('Exact login/password not found in SSH spool')
        print('OK: exact synthetic login and password recorded in private spool',flush=True)
        deadline=time.monotonic()+min(45,max(15,app.CONFIG['import_interval']*3))
        while True:
            with app.credentials_connect() as c:
                row=c.execute('SELECT ip,username,password,profile FROM submissions WHERE username=?',(username,)).fetchone()
            if row:
                if row!=('127.0.0.1',username,password,'ssh'): raise RuntimeError('Imported credentials do not match')
                break
            if time.monotonic()>=deadline: raise RuntimeError('Live dashboard worker did not import the attempt within the timeout')
            time.sleep(.25)
        print('OK: live dashboard worker imported login/password under profile ssh',flush=True)
        body=panel(app)
        if html.escape(username) not in body or html.escape(password) not in body:
            raise RuntimeError('Exact test credentials not present on the authenticated dashboard page')
        print('OK: exact login/password visible in authenticated /credentials page',flush=True)
        passed=True
    except Exception as exc:
        print('TEST FAILED:',type(exc).__name__,str(exc) if isinstance(exc,RuntimeError) else '(details suppressed to avoid exposing credentials)',flush=True)
    finally:
        if transport: transport.close()
        if attempted:
            ids=[]
            try:
                ids=cleanup_spool(spool,username,password)
                print('CLEANUP OK: synthetic login/password removed from SSH spool',flush=True)
            except Exception as exc:
                cleaned=False;print('CLEANUP FAILED: spool:',type(exc).__name__,flush=True)
            try:
                cleanup_credentials(app,username,password,ids)
                print('CLEANUP OK: synthetic login/password removed from dashboard database',flush=True)
            except Exception as exc:
                cleaned=False;print('CLEANUP FAILED: dashboard:',type(exc).__name__,flush=True)
            if cleaned:
                try:
                    if username in panel(app): raise RuntimeError('Test username remains visible')
                    print('CLEANUP OK: test entry absent from dashboard; other entries preserved',flush=True)
                except Exception as exc:
                    cleaned=False;print('CLEANUP FAILED: final page verification:',type(exc).__name__,flush=True)
    if passed and cleaned:
        print('PASS: live SSH capture and cleanup verified. No administrator password was changed.')
        return 0
    print('FAIL: test or cleanup incomplete. Synthetic test username:',username)
    return 1


if __name__=='__main__': sys.exit(main())

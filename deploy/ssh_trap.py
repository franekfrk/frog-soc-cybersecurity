#!/usr/bin/env python3
"""Bounded, authentication-only SSH honeypot. No shell, forwarding or filesystem API."""
import argparse
import datetime
import logging
import os
import secrets
import signal
import socket
import sqlite3
import threading
import time
from pathlib import Path
import paramiko

MAX_CONNECTIONS = 4
SESSION_SECONDS = 30
MAX_ATTEMPTS = 6
SLOTS = threading.BoundedSemaphore(MAX_CONNECTIONS)
WRITE_LOCK = threading.Lock()
STOP = threading.Event()


def connection_db(state):
    c=sqlite3.connect(str(state/'attempts.sqlite3'),timeout=3)
    c.execute('PRAGMA secure_delete=ON')
    c.execute('CREATE TABLE IF NOT EXISTS attempts (id TEXT PRIMARY KEY,ts REAL,ip TEXT,username TEXT,password TEXT)')
    c.commit()
    return c


def record_password(state,ip,username,password):
    with WRITE_LOCK:
        c=connection_db(state)
        try:
            now=time.time()
            c.execute('INSERT INTO attempts VALUES (?,?,?,?,?)',(secrets.token_hex(16),now,ip,username[:256],password[:512]))
            # Bounded spool while the dashboard is unavailable; no secret-bearing log files.
            c.execute('DELETE FROM attempts WHERE ts<?',(now-3600,))
            c.execute('DELETE FROM attempts WHERE id IN (SELECT id FROM attempts ORDER BY ts DESC LIMIT -1 OFFSET 1000)')
            c.commit()
        finally: c.close()


def prune_spool(state):
    with WRITE_LOCK:
        c=connection_db(state)
        try:
            c.execute('DELETE FROM attempts WHERE ts<?',(time.time()-3600,));c.commit()
        finally: c.close()


def session_log(state,kind,ip,port,fd,seconds=None):
    stamp=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds')
    extra='n=1/4096' if kind=='ACCEPT' else 'time=%.6f bytes=0' % seconds
    with WRITE_LOCK:
        # Bounded non-secret session history, compatible with the old importer.
        path=state/'sessions.log'
        if path.exists() and path.stat().st_size>1024*1024:
            os.replace(path,state/'sessions.log.1')
        with path.open('a') as f: f.write('%s %s host=%s port=%d fd=%d %s\n' % (stamp,kind,ip,port,fd,extra))


class PasswordTrap(paramiko.ServerInterface):
    def __init__(self,state,ip): self.state=state;self.ip=ip;self.attempts=0
    def get_allowed_auths(self,username): return 'password,keyboard-interactive'
    def check_auth_password(self,username,password):
        self.attempts+=1
        if self.attempts<=MAX_ATTEMPTS:
            record_password(self.state,self.ip,username,password)
        return paramiko.AUTH_FAILED
    def check_auth_interactive(self,username,submethods):
        self.username=username
        return paramiko.InteractiveQuery('','',('Password: ',False))
    def check_auth_interactive_response(self,responses):
        if len(responses)!=1: return paramiko.AUTH_FAILED
        return self.check_auth_password(self.username,responses[0])
    def check_auth_none(self,username): return paramiko.AUTH_FAILED
    def check_auth_publickey(self,username,key): return paramiko.AUTH_FAILED
    def check_channel_request(self,kind,chanid): return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    def check_channel_exec_request(self,channel,command): return False
    def check_channel_shell_request(self,channel): return False
    def check_channel_pty_request(self,*args): return False
    def check_channel_subsystem_request(self,channel,name): return False
    def check_channel_forward_agent_request(self,channel): return False
    def check_channel_x11_request(self,*args): return False
    def check_channel_direct_tcpip_request(self,*args): return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    def check_port_forward_request(self,address,port): return False


def handle(client,peer,key,state):
    started=time.monotonic(); fd=client.fileno();transport=None
    try:
        session_log(state,'ACCEPT',peer[0],peer[1],fd)
        client.settimeout(8)
        transport=paramiko.Transport(client)
        transport.local_version='SSH-2.0-OpenSSH_9.6'
        transport.banner_timeout=8;transport.auth_timeout=SESSION_SECONDS
        transport.add_server_key(key)
        server=PasswordTrap(state,peer[0])
        ready=threading.Event()
        transport.start_server(event=ready,server=server)
        while not STOP.wait(.1) and time.monotonic()-started<SESSION_SECONDS:
            if not transport.is_active() or server.attempts>=MAX_ATTEMPTS: break
    except (OSError,EOFError,sqlite3.Error,paramiko.SSHException):
        pass
    finally:
        if transport: transport.close()
        client.close()
        try: session_log(state,'CLOSE',peer[0],peer[1],fd,time.monotonic()-started)
        finally: SLOTS.release()


def serve(port,state,host='0.0.0.0'):
    os.umask(0o077)
    state=Path(state);state.mkdir(mode=0o700,parents=True,exist_ok=True)
    if state.stat().st_mode & 0o077: raise RuntimeError('State directory must have mode 700')
    with WRITE_LOCK:
        c=connection_db(state);c.close()
    keyfile=state/'host_rsa'
    if not keyfile.exists(): paramiko.RSAKey.generate(2048).write_private_key_file(str(keyfile))
    key=paramiko.RSAKey.from_private_key_file(str(keyfile))
    (state/'sessions.log').touch(mode=0o600,exist_ok=True)
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        listener.bind((host,port));listener.listen(MAX_CONNECTIONS);listener.settimeout(.5)
        last_prune=time.monotonic()
        while not STOP.is_set():
            if time.monotonic()-last_prune>=60:
                prune_spool(state);last_prune=time.monotonic()
            try: client,peer=listener.accept()
            except socket.timeout: continue
            if not SLOTS.acquire(blocking=False): client.close();continue
            try: threading.Thread(target=handle,args=(client,peer,key,state),daemon=True).start()
            except BaseException: client.close();SLOTS.release();raise


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--port',type=int,default=41888)
    parser.add_argument('--state',default='/var/lib/frog-ssh')
    args=parser.parse_args()
    if not 1024<=args.port<=65535: parser.error('port outside 1024..65535')
    logging.getLogger('paramiko').setLevel(logging.CRITICAL)
    for sig in (signal.SIGINT,signal.SIGTERM): signal.signal(sig,lambda *_:STOP.set())
    serve(args.port,args.state)

if __name__=='__main__': main()

